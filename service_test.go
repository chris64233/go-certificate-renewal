package certificaterenewal

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeClock 是可手动推进的时钟。
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestService() (*Service, *InMemoryStore, *fakeClock) {
	store := NewInMemoryStore()
	clock := newFakeClock()
	return NewService(store, clock.Now), store, clock
}

// createOrder 是创建订单的测试辅助，返回订单与 domain -> 明文秘密 的映射。
func createOrder(t *testing.T, s *Service, domains []string, ttl time.Duration) (Order, map[string]string) {
	t.Helper()
	order, challenges, err := s.CreateOrder(CreateOrderInput{
		Domains:  domains,
		Deadline: time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC).Add(ttl),
	})
	if err != nil {
		t.Fatalf("CreateOrder: %v", err)
	}
	secrets := make(map[string]string, len(challenges))
	for _, c := range challenges {
		secrets[c.Challenge.Domain] = c.Secret
	}
	return order, secrets
}

func callback(domain, callbackID, secret string, succeeded bool) CallbackInput {
	return CallbackInput{
		Domain:     domain,
		CallbackID: callbackID,
		Secret:     secret,
		Succeeded:  succeeded,
	}
}

func TestCreateOrderFreezesDomainsAndDeadline(t *testing.T) {
	s, _, clock := newTestService()
	deadline := clock.Now().Add(time.Hour)

	order, challenges, err := s.CreateOrder(CreateOrderInput{
		Domains:  []string{"b.example.com", "a.example.com", "a.example.com"},
		Deadline: deadline,
	})
	if err != nil {
		t.Fatalf("CreateOrder: %v", err)
	}

	// 域名集合被冻结：去重并排序。
	want := []string{"a.example.com", "b.example.com"}
	if len(order.Domains) != len(want) {
		t.Fatalf("domains = %v, want %v", order.Domains, want)
	}
	for i := range want {
		if order.Domains[i] != want[i] {
			t.Fatalf("domains = %v, want %v", order.Domains, want)
		}
	}
	if !order.Deadline.Equal(deadline) {
		t.Fatalf("deadline = %s, want %s", order.Deadline, deadline)
	}
	if order.Status != OrderStatusPending {
		t.Fatalf("status = %s, want PENDING", order.Status)
	}

	// 每个域名单独生成挑战，且只持久化摘要。
	if len(challenges) != 2 {
		t.Fatalf("challenges = %d, want 2", len(challenges))
	}
	view, err := s.GetOrder(order.ID)
	if err != nil {
		t.Fatalf("GetOrder: %v", err)
	}
	for _, c := range challenges {
		sum := sha256.Sum256([]byte(c.Secret))
		wantDigest := hex.EncodeToString(sum[:])
		if c.Challenge.SecretDigest != wantDigest {
			t.Errorf("domain %s: stored digest is not sha256 of secret", c.Challenge.Domain)
		}
		if c.Challenge.SecretDigest == c.Secret {
			t.Errorf("domain %s: plaintext secret persisted as digest", c.Challenge.Domain)
		}
	}
	if len(view.Challenges) != 2 {
		t.Fatalf("persisted challenges = %d, want 2", len(view.Challenges))
	}
}

func TestCreateOrderValidation(t *testing.T) {
	s, _, clock := newTestService()

	if _, _, err := s.CreateOrder(CreateOrderInput{
		Domains:  nil,
		Deadline: clock.Now().Add(time.Hour),
	}); !IsKind(err, KindInvalid) {
		t.Errorf("empty domains: err = %v, want KindInvalid", err)
	}
	if _, _, err := s.CreateOrder(CreateOrderInput{
		Domains:  []string{""},
		Deadline: clock.Now().Add(time.Hour),
	}); !IsKind(err, KindInvalid) {
		t.Errorf("empty domain: err = %v, want KindInvalid", err)
	}
	if _, _, err := s.CreateOrder(CreateOrderInput{
		Domains:  []string{"a.example.com"},
		Deadline: clock.Now().Add(-time.Minute),
	}); !IsKind(err, KindInvalid) {
		t.Errorf("past deadline: err = %v, want KindInvalid", err)
	}
}

func TestCallbackCompletesOrderAndWritesSingleOutbox(t *testing.T) {
	s, _, _ := newTestService()
	order, secrets := createOrder(t, s, []string{"a.example.com", "b.example.com"}, time.Hour)

	// 第一个域名成功：订单仍为 PENDING，无 outbox。
	res, err := s.HandleChallengeCallback(CallbackInput{
		OrderID: order.ID, Domain: "a.example.com",
		CallbackID: "cb-1", Secret: secrets["a.example.com"], Succeeded: true,
	})
	if err != nil {
		t.Fatalf("callback a: %v", err)
	}
	if res.ChallengeStatus != ChallengeStatusSucceeded || res.OrderStatus != OrderStatusPending {
		t.Fatalf("result = %+v, want challenge SUCCEEDED / order PENDING", res)
	}
	if outbox, _ := s.ListOutbox(); len(outbox) != 0 {
		t.Fatalf("outbox = %d, want 0", len(outbox))
	}

	// 最后一个域名成功：订单原子转为待签发，恰好一条 outbox。
	res, err = s.HandleChallengeCallback(CallbackInput{
		OrderID: order.ID, Domain: "b.example.com",
		CallbackID: "cb-2", Secret: secrets["b.example.com"], Succeeded: true,
	})
	if err != nil {
		t.Fatalf("callback b: %v", err)
	}
	if res.OrderStatus != OrderStatusReadyForIssuance {
		t.Fatalf("order status = %s, want READY_FOR_ISSUANCE", res.OrderStatus)
	}
	outbox, _ := s.ListOutbox()
	if len(outbox) != 1 {
		t.Fatalf("outbox = %d, want 1", len(outbox))
	}
	if outbox[0].OrderID != order.ID || outbox[0].Type != TypeIssuanceRequested {
		t.Fatalf("outbox message = %+v", outbox[0])
	}
}

func TestCallbackFailureDoesNotPolluteOtherDomains(t *testing.T) {
	s, _, _ := newTestService()
	order, secrets := createOrder(t, s, []string{"a.example.com", "b.example.com"}, time.Hour)

	in := callback("a.example.com", "cb-fail", secrets["a.example.com"], false)
	in.OrderID = order.ID
	in.FailureReason = "dns timeout"
	res, err := s.HandleChallengeCallback(in)
	if err != nil {
		t.Fatalf("callback fail: %v", err)
	}
	if res.ChallengeStatus != ChallengeStatusFailed {
		t.Fatalf("challenge status = %s, want FAILED", res.ChallengeStatus)
	}

	// 另一个域名不受污染，仍可正常成功。
	res, err = s.HandleChallengeCallback(CallbackInput{
		OrderID: order.ID, Domain: "b.example.com",
		CallbackID: "cb-ok", Secret: secrets["b.example.com"], Succeeded: true,
	})
	if err != nil {
		t.Fatalf("callback b: %v", err)
	}
	if res.ChallengeStatus != ChallengeStatusSucceeded {
		t.Fatalf("b challenge status = %s, want SUCCEEDED", res.ChallengeStatus)
	}

	view, _ := s.GetOrder(order.ID)
	if view.Order.Status != OrderStatusPending {
		t.Fatalf("order status = %s, want PENDING", view.Order.Status)
	}
	for _, c := range view.Challenges {
		if c.Domain == "a.example.com" && c.FailureReason != "dns timeout" {
			t.Errorf("failure reason = %q, want %q", c.FailureReason, "dns timeout")
		}
	}
	if outbox, _ := s.ListOutbox(); len(outbox) != 0 {
		t.Fatalf("outbox = %d, want 0", len(outbox))
	}
}

func TestCallbackIdempotency(t *testing.T) {
	s, _, _ := newTestService()
	order, secrets := createOrder(t, s, []string{"a.example.com"}, time.Hour)
	in := CallbackInput{
		OrderID: order.ID, Domain: "a.example.com",
		CallbackID: "cb-1", Secret: secrets["a.example.com"], Succeeded: true,
	}

	first, err := s.HandleChallengeCallback(in)
	if err != nil {
		t.Fatalf("first callback: %v", err)
	}

	// 同号同内容：复用原结果，不重复产生 outbox。
	second, err := s.HandleChallengeCallback(in)
	if err != nil {
		t.Fatalf("duplicate callback: %v", err)
	}
	if !second.Duplicate {
		t.Errorf("duplicate callback not marked as duplicate")
	}
	if second.ChallengeStatus != first.ChallengeStatus || second.OrderStatus != first.OrderStatus {
		t.Errorf("replayed result %+v differs from first %+v", second, first)
	}
	if outbox, _ := s.ListOutbox(); len(outbox) != 1 {
		t.Errorf("outbox = %d, want exactly 1", len(outbox))
	}

	// 同号异内容：幂等冲突。
	conflict := in
	conflict.Succeeded = false
	conflict.FailureReason = "changed"
	if _, err := s.HandleChallengeCallback(conflict); !IsKind(err, KindIdempotency) {
		t.Errorf("same id different content: err = %v, want KindIdempotency", err)
	}
}

func TestCallbackAuthFailure(t *testing.T) {
	s, _, _ := newTestService()
	order, secrets := createOrder(t, s, []string{"a.example.com"}, time.Hour)

	in := CallbackInput{
		OrderID: order.ID, Domain: "a.example.com",
		CallbackID: "cb-1", Secret: "wrong-secret", Succeeded: true,
	}
	if _, err := s.HandleChallengeCallback(in); !IsKind(err, KindAuth) {
		t.Fatalf("wrong secret: err = %v, want KindAuth", err)
	}

	// 认证失败不占用回调号：同一回调号携带正确秘密仍可处理。
	in.Secret = secrets["a.example.com"]
	res, err := s.HandleChallengeCallback(in)
	if err != nil {
		t.Fatalf("retry with correct secret: %v", err)
	}
	if res.ChallengeStatus != ChallengeStatusSucceeded {
		t.Fatalf("challenge status = %s, want SUCCEEDED", res.ChallengeStatus)
	}
}

func TestCallbackUnknownOrderAndDomain(t *testing.T) {
	s, _, _ := newTestService()
	order, _ := createOrder(t, s, []string{"a.example.com"}, time.Hour)

	if _, err := s.HandleChallengeCallback(CallbackInput{
		OrderID: "no-such-order", Domain: "a.example.com", CallbackID: "cb-1", Secret: "x",
	}); !IsKind(err, KindNotFound) {
		t.Errorf("unknown order: err = %v, want KindNotFound", err)
	}
	if _, err := s.HandleChallengeCallback(CallbackInput{
		OrderID: order.ID, Domain: "other.example.com", CallbackID: "cb-2", Secret: "x",
	}); !IsKind(err, KindNotFound) {
		t.Errorf("unknown domain: err = %v, want KindNotFound", err)
	}
}

func TestCancelThenCallbackCannotRevive(t *testing.T) {
	s, _, _ := newTestService()
	order, secrets := createOrder(t, s, []string{"a.example.com"}, time.Hour)

	cancelled, err := s.CancelOrder(order.ID)
	if err != nil {
		t.Fatalf("CancelOrder: %v", err)
	}
	if cancelled.Status != OrderStatusCancelled {
		t.Fatalf("status = %s, want CANCELLED", cancelled.Status)
	}

	// 取消后到达的成功回调不能复活订单。
	_, err = s.HandleChallengeCallback(CallbackInput{
		OrderID: order.ID, Domain: "a.example.com",
		CallbackID: "cb-late", Secret: secrets["a.example.com"], Succeeded: true,
	})
	if !IsKind(err, KindState) {
		t.Fatalf("late callback: err = %v, want KindState", err)
	}
	view, _ := s.GetOrder(order.ID)
	if view.Order.Status != OrderStatusCancelled {
		t.Fatalf("order revived to %s", view.Order.Status)
	}
	if outbox, _ := s.ListOutbox(); len(outbox) != 0 {
		t.Fatalf("outbox = %d, want 0", len(outbox))
	}

	// 重复取消幂等。
	if again, err := s.CancelOrder(order.ID); err != nil || again.Status != OrderStatusCancelled {
		t.Fatalf("re-cancel: status = %s, err = %v", again.Status, err)
	}
}

func TestExpiryThenCallbackCannotRevive(t *testing.T) {
	s, _, clock := newTestService()
	order, secrets := createOrder(t, s, []string{"a.example.com"}, time.Hour)

	clock.Advance(2 * time.Hour)
	expired, err := s.AdvanceExpiry()
	if err != nil {
		t.Fatalf("AdvanceExpiry: %v", err)
	}
	if len(expired) != 1 || expired[0] != order.ID {
		t.Fatalf("expired = %v, want [%s]", expired, order.ID)
	}

	// 过期后到达的成功回调不能复活订单。
	_, err = s.HandleChallengeCallback(CallbackInput{
		OrderID: order.ID, Domain: "a.example.com",
		CallbackID: "cb-late", Secret: secrets["a.example.com"], Succeeded: true,
	})
	if !IsKind(err, KindState) {
		t.Fatalf("late callback: err = %v, want KindState", err)
	}
	view, _ := s.GetOrder(order.ID)
	if view.Order.Status != OrderStatusExpired {
		t.Fatalf("order revived to %s", view.Order.Status)
	}

	// 过期订单不可取消、不可签发。
	if _, err := s.CancelOrder(order.ID); !IsKind(err, KindState) {
		t.Errorf("cancel expired: err = %v, want KindState", err)
	}
	if _, err := s.ConfirmIssuance(order.ID); !IsKind(err, KindState) {
		t.Errorf("confirm expired: err = %v, want KindState", err)
	}
}

func TestLazyExpiryOnCallback(t *testing.T) {
	s, _, clock := newTestService()
	order, secrets := createOrder(t, s, []string{"a.example.com"}, time.Hour)

	// 未运行过期推进，但回调到达时已超过截止时间：惰性过期。
	clock.Advance(2 * time.Hour)
	_, err := s.HandleChallengeCallback(CallbackInput{
		OrderID: order.ID, Domain: "a.example.com",
		CallbackID: "cb-1", Secret: secrets["a.example.com"], Succeeded: true,
	})
	if !IsKind(err, KindExpired) {
		t.Fatalf("callback after deadline: err = %v, want KindExpired", err)
	}
	view, _ := s.GetOrder(order.ID)
	if view.Order.Status != OrderStatusExpired {
		t.Fatalf("status = %s, want EXPIRED", view.Order.Status)
	}
}

func TestIssuedOrderDuplicateCallbackStable(t *testing.T) {
	s, _, _ := newTestService()
	order, secrets := createOrder(t, s, []string{"a.example.com"}, time.Hour)
	in := CallbackInput{
		OrderID: order.ID, Domain: "a.example.com",
		CallbackID: "cb-1", Secret: secrets["a.example.com"], Succeeded: true,
	}
	if _, err := s.HandleChallengeCallback(in); err != nil {
		t.Fatalf("callback: %v", err)
	}
	if _, err := s.ConfirmIssuance(order.ID); err != nil {
		t.Fatalf("ConfirmIssuance: %v", err)
	}

	// 签发完成后，重复回调仍返回与首次一致的稳定结果。
	res, err := s.HandleChallengeCallback(in)
	if err != nil {
		t.Fatalf("duplicate callback after issuance: %v", err)
	}
	if !res.Duplicate || res.ChallengeStatus != ChallengeStatusSucceeded {
		t.Fatalf("result = %+v, want duplicate SUCCEEDED", res)
	}

	// 新回调号也不再改变状态，返回稳定结果。
	res, err = s.HandleChallengeCallback(CallbackInput{
		OrderID: order.ID, Domain: "a.example.com",
		CallbackID: "cb-2", Secret: secrets["a.example.com"], Succeeded: false,
		FailureReason: "too late",
	})
	if err != nil {
		t.Fatalf("new callback after issuance: %v", err)
	}
	if res.OrderStatus != OrderStatusIssued {
		t.Fatalf("order status = %s, want ISSUED", res.OrderStatus)
	}
	view, _ := s.GetOrder(order.ID)
	if view.Order.Status != OrderStatusIssued {
		t.Fatalf("order changed to %s", view.Order.Status)
	}

	// 已签发订单不可取消；重复确认幂等。
	if _, err := s.CancelOrder(order.ID); !IsKind(err, KindState) {
		t.Errorf("cancel issued: err = %v, want KindState", err)
	}
	if again, err := s.ConfirmIssuance(order.ID); err != nil || again.Status != OrderStatusIssued {
		t.Errorf("re-confirm: status = %s, err = %v", again.Status, err)
	}
}

func TestConfirmIssuanceRequiresReadyOrder(t *testing.T) {
	s, _, _ := newTestService()
	order, _ := createOrder(t, s, []string{"a.example.com"}, time.Hour)

	if _, err := s.ConfirmIssuance(order.ID); !IsKind(err, KindState) {
		t.Fatalf("confirm pending: err = %v, want KindState", err)
	}
}

func TestGetOrderNotFound(t *testing.T) {
	s, _, _ := newTestService()
	if _, err := s.GetOrder("missing"); !IsKind(err, KindNotFound) {
		t.Fatalf("err = %v, want KindNotFound", err)
	}
}

func TestConcurrentFinalCallbacksWriteExactlyOneOutbox(t *testing.T) {
	s, _, _ := newTestService()
	domains := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"}
	order, secrets := createOrder(t, s, domains, time.Hour)

	var wg sync.WaitGroup
	errs := make(chan error, 2*len(domains))
	for i, d := range domains {
		// 每个域名的同一回调并发投递两次，模拟重复到达。
		for range 2 {
			wg.Add(1)
			go func(domain, id string) {
				defer wg.Done()
				_, err := s.HandleChallengeCallback(CallbackInput{
					OrderID: order.ID, Domain: domain,
					CallbackID: id, Secret: secrets[domain], Succeeded: true,
				})
				errs <- err
			}(d, fmt.Sprintf("cb-%d", i))
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent callback: %v", err)
		}
	}

	view, _ := s.GetOrder(order.ID)
	if view.Order.Status != OrderStatusReadyForIssuance {
		t.Fatalf("status = %s, want READY_FOR_ISSUANCE", view.Order.Status)
	}
	outbox, _ := s.ListOutbox()
	if len(outbox) != 1 {
		t.Fatalf("outbox = %d, want exactly 1", len(outbox))
	}
}

func TestConcurrentSameCallbackIDRace(t *testing.T) {
	s, _, _ := newTestService()
	order, secrets := createOrder(t, s, []string{"a.example.com"}, time.Hour)

	// 同一回调号并发到达多次：全部返回一致结果，outbox 恰好一条。
	var wg sync.WaitGroup
	results := make(chan CallbackResult, 16)
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := s.HandleChallengeCallback(CallbackInput{
				OrderID: order.ID, Domain: "a.example.com",
				CallbackID: "cb-1", Secret: secrets["a.example.com"], Succeeded: true,
			})
			results <- res
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent duplicate: %v", err)
		}
	}
	for res := range results {
		if res.ChallengeStatus != ChallengeStatusSucceeded || res.OrderStatus != OrderStatusReadyForIssuance {
			t.Fatalf("inconsistent result: %+v", res)
		}
	}
	if outbox, _ := s.ListOutbox(); len(outbox) != 1 {
		t.Fatalf("outbox = %d, want exactly 1", len(outbox))
	}
}

func TestCancelConfirmIssuanceRaceIsDeterministic(t *testing.T) {
	for i := 0; i < 50; i++ {
		s, _, _ := newTestService()
		order, secrets := createOrder(t, s, []string{"a.example.com"}, time.Hour)
		if _, err := s.HandleChallengeCallback(CallbackInput{
			OrderID: order.ID, Domain: "a.example.com",
			CallbackID: "cb-1", Secret: secrets["a.example.com"], Succeeded: true,
		}); err != nil {
			t.Fatalf("callback: %v", err)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		var cancelErr, confirmErr error
		go func() { defer wg.Done(); _, cancelErr = s.CancelOrder(order.ID) }()
		go func() { defer wg.Done(); _, confirmErr = s.ConfirmIssuance(order.ID) }()
		wg.Wait()

		view, _ := s.GetOrder(order.ID)
		switch view.Order.Status {
		case OrderStatusCancelled:
			if cancelErr != nil || !IsKind(confirmErr, KindState) {
				t.Fatalf("cancelled but cancelErr=%v confirmErr=%v", cancelErr, confirmErr)
			}
		case OrderStatusIssued:
			if confirmErr != nil || !IsKind(cancelErr, KindState) {
				t.Fatalf("issued but cancelErr=%v confirmErr=%v", cancelErr, confirmErr)
			}
		default:
			t.Fatalf("unexpected final status %s", view.Order.Status)
		}
	}
}

func TestCallbackCancelRaceNeverRevives(t *testing.T) {
	for i := 0; i < 50; i++ {
		s, _, _ := newTestService()
		order, secrets := createOrder(t, s, []string{"a.example.com"}, time.Hour)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = s.HandleChallengeCallback(CallbackInput{
				OrderID: order.ID, Domain: "a.example.com",
				CallbackID: "cb-1", Secret: secrets["a.example.com"], Succeeded: true,
			})
		}()
		go func() { defer wg.Done(); _, _ = s.CancelOrder(order.ID) }()
		wg.Wait()

		view, _ := s.GetOrder(order.ID)
		outbox, _ := s.ListOutbox()
		switch view.Order.Status {
		case OrderStatusCancelled:
			// 取消获胜：可能是在回调前（无 outbox）或回调后（有 outbox 但订单已取消）。
			if len(outbox) > 1 {
				t.Fatalf("outbox = %d, want at most 1", len(outbox))
			}
		case OrderStatusReadyForIssuance:
			if len(outbox) != 1 {
				t.Fatalf("ready but outbox = %d", len(outbox))
			}
		default:
			t.Fatalf("unexpected final status %s", view.Order.Status)
		}
	}
}
