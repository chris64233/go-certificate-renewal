package certificaterenewal

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestService(t *testing.T, clock *fakeClock) *Service {
	t.Helper()
	svc, err := NewService(NewMemoryPersister(), WithClock(clock.Now), WithDigestKey([]byte("test-key")))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func mustCreate(t *testing.T, svc *Service, id string, domains []string, ttl time.Duration) *CreateOrderResult {
	t.Helper()
	res, err := svc.CreateOrder(CreateOrderInput{OrderID: id, Domains: domains, TTL: ttl})
	if err != nil {
		t.Fatalf("CreateOrder: %v", err)
	}
	return res
}

func mustCallback(t *testing.T, svc *Service, orderID, domain, cbID, secret string, outcome Outcome) *CallbackResult {
	t.Helper()
	res, err := svc.HandleCallback(CallbackInput{
		OrderID: orderID, Domain: domain, CallbackID: cbID, Secret: secret, Outcome: outcome,
	})
	if err != nil {
		t.Fatalf("HandleCallback(%s/%s): %v", orderID, domain, err)
	}
	return res
}

func requireKind(t *testing.T, err error, want Kind) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error, got nil", want)
	}
	if kind, ok := KindOf(err); !ok || kind != want {
		t.Fatalf("expected %s error, got %v", want, err)
	}
}

func TestCreateOrderFreezesDomainsAndDeadline(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, clock)

	res := mustCreate(t, svc, "o1", []string{"B.example.com", "a.example.com"}, time.Hour)

	if res.Reused {
		t.Fatal("first create should not be reused")
	}
	wantDomains := []string{"a.example.com", "b.example.com"}
	if fmt.Sprint(res.Order.Domains) != fmt.Sprint(wantDomains) {
		t.Fatalf("domains not normalized/frozen: %v", res.Order.Domains)
	}
	if !res.Order.Deadline.Equal(clock.Now().Add(time.Hour)) {
		t.Fatalf("deadline = %v, want %v", res.Order.Deadline, clock.Now().Add(time.Hour))
	}
	if len(res.Secrets) != 2 || len(res.Order.Challenges) != 2 {
		t.Fatalf("expected per-domain challenges and secrets, got %+v", res)
	}
	for _, ch := range res.Order.Challenges {
		if ch.Status != ChallengeStatusPending {
			t.Fatalf("challenge %s status = %s", ch.Domain, ch.Status)
		}
		if res.Secrets[ch.Domain] == "" {
			t.Fatalf("missing secret for %s", ch.Domain)
		}
	}
}

func TestCreateOrderRejectsBadInput(t *testing.T) {
	svc := newTestService(t, newFakeClock())

	if _, err := svc.CreateOrder(CreateOrderInput{Domains: nil, TTL: time.Hour}); err == nil {
		t.Fatal("empty domains should fail")
	} else {
		requireKind(t, err, KindValidation)
	}
	if _, err := svc.CreateOrder(CreateOrderInput{Domains: []string{"a.com", "A.com"}, TTL: time.Hour}); err == nil {
		t.Fatal("duplicate domains should fail")
	} else {
		requireKind(t, err, KindValidation)
	}
	if _, err := svc.CreateOrder(CreateOrderInput{Domains: []string{"a.com"}, TTL: 0}); err == nil {
		t.Fatal("non-positive ttl should fail")
	} else {
		requireKind(t, err, KindValidation)
	}
}

func TestCreateOrderIdempotent(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, clock)
	domains := []string{"a.example.com"}

	first := mustCreate(t, svc, "o1", domains, time.Hour)
	second, err := svc.CreateOrder(CreateOrderInput{OrderID: "o1", Domains: domains, TTL: time.Hour})
	if err != nil {
		t.Fatalf("idempotent create: %v", err)
	}
	if !second.Reused || len(second.Secrets) != 0 {
		t.Fatalf("expected reused result without secrets, got %+v", second)
	}
	if second.Order.Status != first.Order.Status {
		t.Fatal("reused order state mismatch")
	}

	_, err = svc.CreateOrder(CreateOrderInput{OrderID: "o1", Domains: []string{"other.com"}, TTL: time.Hour})
	requireKind(t, err, KindConflict)
}

func TestSecretOnlyStoredAsDigest(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	res := mustCreate(t, svc, "o1", []string{"a.example.com"}, time.Hour)

	stored := svc.data.Orders["o1"].Challenges["a.example.com"]
	secret := res.Secrets["a.example.com"]
	if stored.SecretDigest == "" || stored.SecretDigest == secret {
		t.Fatalf("secret must be persisted as digest only, got %q", stored.SecretDigest)
	}
	// 摘要绑定订单与域名：换域名后同一秘密摘要不成立。
	if svc.digestSecret("o1", "other.example.com", secret) == stored.SecretDigest {
		t.Fatal("digest must be bound to domain")
	}
}

func TestCallbackSuccessFlowEmitsSingleOutbox(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	res := mustCreate(t, svc, "o1", []string{"a.example.com", "b.example.com"}, time.Hour)

	r1 := mustCallback(t, svc, "o1", "a.example.com", "cb-1", res.Secrets["a.example.com"], OutcomeSuccess)
	if r1.OrderStatus != OrderStatusActive {
		t.Fatalf("order should stay active with one domain pending, got %s", r1.OrderStatus)
	}
	r2 := mustCallback(t, svc, "o1", "b.example.com", "cb-2", res.Secrets["b.example.com"], OutcomeSuccess)
	if r2.OrderStatus != OrderStatusPendingIssuance {
		t.Fatalf("order should be pending_issuance, got %s", r2.OrderStatus)
	}

	outbox := svc.ListOutbox()
	if len(outbox) != 1 {
		t.Fatalf("expected exactly one outbox message, got %d", len(outbox))
	}
	if outbox[0].OrderID != "o1" || outbox[0].Status != OutboxStatusPending {
		t.Fatalf("unexpected outbox message: %+v", outbox[0])
	}
}

func TestCallbackReplaySameContentReusesResult(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	res := mustCreate(t, svc, "o1", []string{"a.example.com"}, time.Hour)
	secret := res.Secrets["a.example.com"]

	first := mustCallback(t, svc, "o1", "a.example.com", "cb-1", secret, OutcomeSuccess)
	replay := mustCallback(t, svc, "o1", "a.example.com", "cb-1", secret, OutcomeSuccess)

	if first.Reused {
		t.Fatal("first delivery should not be reused")
	}
	if !replay.Reused {
		t.Fatal("replay should reuse stored result")
	}
	if replay.ChallengeStatus != first.ChallengeStatus || replay.OrderStatus != first.OrderStatus {
		t.Fatal("replayed result must equal original result")
	}
	if n := len(svc.ListOutbox()); n != 1 {
		t.Fatalf("replay must not duplicate outbox, got %d", n)
	}
}

func TestCallbackSameIDDifferentContentConflicts(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	res := mustCreate(t, svc, "o1", []string{"a.example.com"}, time.Hour)
	secret := res.Secrets["a.example.com"]

	mustCallback(t, svc, "o1", "a.example.com", "cb-1", secret, OutcomeFailure)

	_, err := svc.HandleCallback(CallbackInput{
		OrderID: "o1", Domain: "a.example.com", CallbackID: "cb-1", Secret: secret, Outcome: OutcomeSuccess,
	})
	requireKind(t, err, KindConflict)
}

func TestCallbackWrongSecretIsAuthError(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustCreate(t, svc, "o1", []string{"a.example.com"}, time.Hour)

	_, err := svc.HandleCallback(CallbackInput{
		OrderID: "o1", Domain: "a.example.com", CallbackID: "cb-1", Secret: "forged", Outcome: OutcomeSuccess,
	})
	requireKind(t, err, KindAuth)

	view, _ := svc.GetOrder("o1")
	if view.Challenges[0].Status != ChallengeStatusPending {
		t.Fatal("auth failure must not mutate challenge")
	}
}

func TestCallbackUnknownOrderOrDomain(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	res := mustCreate(t, svc, "o1", []string{"a.example.com"}, time.Hour)

	_, err := svc.HandleCallback(CallbackInput{
		OrderID: "nope", Domain: "a.example.com", CallbackID: "cb-1", Secret: "x", Outcome: OutcomeSuccess,
	})
	requireKind(t, err, KindNotFound)

	_, err = svc.HandleCallback(CallbackInput{
		OrderID: "o1", Domain: "stranger.example.com", CallbackID: "cb-1",
		Secret: res.Secrets["a.example.com"], Outcome: OutcomeSuccess,
	})
	requireKind(t, err, KindNotFound)
}

func TestDomainFailureDoesNotPolluteOthers(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	res := mustCreate(t, svc, "o1", []string{"a.example.com", "b.example.com"}, time.Hour)

	r := mustCallback(t, svc, "o1", "a.example.com", "cb-1", res.Secrets["a.example.com"], OutcomeFailure)
	if r.ChallengeStatus != ChallengeStatusFailed || r.OrderStatus != OrderStatusActive {
		t.Fatalf("unexpected result: %+v", r)
	}

	r2 := mustCallback(t, svc, "o1", "b.example.com", "cb-2", res.Secrets["b.example.com"], OutcomeSuccess)
	if r2.ChallengeStatus != ChallengeStatusSucceeded {
		t.Fatalf("other domain must be unaffected, got %s", r2.ChallengeStatus)
	}

	view, _ := svc.GetOrder("o1")
	statuses := map[string]ChallengeStatus{}
	for _, ch := range view.Challenges {
		statuses[ch.Domain] = ch.Status
	}
	if statuses["a.example.com"] != ChallengeStatusFailed || statuses["b.example.com"] != ChallengeStatusSucceeded {
		t.Fatalf("per-domain isolation broken: %v", statuses)
	}

	// 已终结的挑战不能再用新回调号覆盖。
	_, err := svc.HandleCallback(CallbackInput{
		OrderID: "o1", Domain: "a.example.com", CallbackID: "cb-3",
		Secret: res.Secrets["a.example.com"], Outcome: OutcomeSuccess,
	})
	requireKind(t, err, KindState)
}

func TestConcurrentFinalCallbacksEmitExactlyOneOutbox(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	domains := []string{"a.example.com", "b.example.com", "c.example.com"}
	res := mustCreate(t, svc, "o1", domains, time.Hour)
	for _, d := range domains[:2] {
		mustCallback(t, svc, "o1", d, "cb-"+d, res.Secrets[d], OutcomeSuccess)
	}

	// 多个“最后一个回调”并发到达：不同回调号、同一域名、同一成功结果。
	const racers = 32
	var wg sync.WaitGroup
	errs := make([]error, racers)
	results := make([]*CallbackResult, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := svc.HandleCallback(CallbackInput{
				OrderID: "o1", Domain: "c.example.com", CallbackID: fmt.Sprintf("cb-final-%d", i),
				Secret: res.Secrets["c.example.com"], Outcome: OutcomeSuccess,
			})
			errs[i], results[i] = err, r
		}(i)
	}
	wg.Wait()

	applied := 0
	for i := range racers {
		if errs[i] == nil {
			applied++
			if results[i].OrderStatus != OrderStatusPendingIssuance {
				t.Fatalf("winner should observe pending_issuance, got %s", results[i].OrderStatus)
			}
		} else {
			requireKind(t, errs[i], KindState)
		}
	}
	if applied != 1 {
		t.Fatalf("exactly one concurrent callback may apply, got %d", applied)
	}
	if n := len(svc.ListOutbox()); n != 1 {
		t.Fatalf("exactly one outbox message expected, got %d", n)
	}
}

func TestConcurrentDuplicateCallbacksAllReuse(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	res := mustCreate(t, svc, "o1", []string{"a.example.com"}, time.Hour)

	const racers = 32
	var wg sync.WaitGroup
	reused := make([]bool, racers)
	errs := make([]error, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := svc.HandleCallback(CallbackInput{
				OrderID: "o1", Domain: "a.example.com", CallbackID: "cb-dup",
				Secret: res.Secrets["a.example.com"], Outcome: OutcomeSuccess,
			})
			if err == nil {
				reused[i] = r.Reused
			}
			errs[i] = err
		}(i)
	}
	wg.Wait()

	fresh := 0
	for i := range racers {
		if errs[i] != nil {
			t.Fatalf("duplicate delivery must succeed, got %v", errs[i])
		}
		if !reused[i] {
			fresh++
		}
	}
	if fresh != 1 {
		t.Fatalf("exactly one delivery should be fresh, got %d", fresh)
	}
	if n := len(svc.ListOutbox()); n != 1 {
		t.Fatalf("exactly one outbox message expected, got %d", n)
	}
}

func TestCancelThenLateSuccessCannotRevive(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	res := mustCreate(t, svc, "o1", []string{"a.example.com"}, time.Hour)

	view, err := svc.CancelOrder("o1")
	if err != nil || view.Status != OrderStatusCancelled {
		t.Fatalf("cancel: %v %+v", err, view)
	}

	_, err = svc.HandleCallback(CallbackInput{
		OrderID: "o1", Domain: "a.example.com", CallbackID: "cb-late",
		Secret: res.Secrets["a.example.com"], Outcome: OutcomeSuccess,
	})
	requireKind(t, err, KindState)

	view, _ = svc.GetOrder("o1")
	if view.Status != OrderStatusCancelled || view.Challenges[0].Status != ChallengeStatusPending {
		t.Fatalf("late callback revived order: %+v", view)
	}
	if n := len(svc.ListOutbox()); n != 0 {
		t.Fatalf("cancelled order must not emit outbox, got %d", n)
	}
}

func TestCancelPendingIssuanceVoidsOutbox(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	res := mustCreate(t, svc, "o1", []string{"a.example.com"}, time.Hour)
	mustCallback(t, svc, "o1", "a.example.com", "cb-1", res.Secrets["a.example.com"], OutcomeSuccess)

	view, err := svc.CancelOrder("o1")
	if err != nil || view.Status != OrderStatusCancelled {
		t.Fatalf("cancel pending_issuance: %v %+v", err, view)
	}
	outbox := svc.ListOutbox()
	if len(outbox) != 1 || outbox[0].Status != OutboxStatusCancelled {
		t.Fatalf("outbox should be voided, got %+v", outbox)
	}
	if _, err := svc.ConfirmIssuance("o1", "iss-1"); err == nil {
		t.Fatal("cancelled order must not confirm issuance")
	} else {
		requireKind(t, err, KindState)
	}
}

func TestCancelIsIdempotentAndDeterministic(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustCreate(t, svc, "o1", []string{"a.example.com"}, time.Hour)

	if _, err := svc.CancelOrder("o1"); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	view, err := svc.CancelOrder("o1")
	if err != nil || view.Status != OrderStatusCancelled {
		t.Fatalf("repeat cancel should be stable: %v %+v", err, view)
	}
}

func TestExpiryBlocksLateCallbacksAndCancel(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, clock)
	res := mustCreate(t, svc, "o1", []string{"a.example.com"}, time.Hour)

	clock.Advance(2 * time.Hour)
	expired, err := svc.AdvanceExpiry()
	if err != nil || len(expired) != 1 || expired[0] != "o1" {
		t.Fatalf("AdvanceExpiry: %v %v", err, expired)
	}

	_, err = svc.HandleCallback(CallbackInput{
		OrderID: "o1", Domain: "a.example.com", CallbackID: "cb-late",
		Secret: res.Secrets["a.example.com"], Outcome: OutcomeSuccess,
	})
	requireKind(t, err, KindExpired)

	_, err = svc.CancelOrder("o1")
	requireKind(t, err, KindExpired)

	view, _ := svc.GetOrder("o1")
	if view.Status != OrderStatusExpired || view.Challenges[0].Status != ChallengeStatusPending {
		t.Fatalf("expiry must be terminal: %+v", view)
	}
}

func TestLazyExpiryOnCallbackWithoutSweep(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, clock)
	res := mustCreate(t, svc, "o1", []string{"a.example.com"}, time.Hour)

	clock.Advance(time.Hour + time.Second) // 未调用 AdvanceExpiry

	_, err := svc.HandleCallback(CallbackInput{
		OrderID: "o1", Domain: "a.example.com", CallbackID: "cb-1",
		Secret: res.Secrets["a.example.com"], Outcome: OutcomeSuccess,
	})
	requireKind(t, err, KindExpired)

	view, _ := svc.GetOrder("o1")
	if view.Status != OrderStatusExpired {
		t.Fatalf("callback past deadline must lazily expire order, got %s", view.Status)
	}
}

func TestConfirmIssuanceFlow(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	res := mustCreate(t, svc, "o1", []string{"a.example.com"}, time.Hour)

	if _, err := svc.ConfirmIssuance("o1", "iss-1"); err == nil {
		t.Fatal("active order cannot confirm issuance")
	} else {
		requireKind(t, err, KindState)
	}

	mustCallback(t, svc, "o1", "a.example.com", "cb-1", res.Secrets["a.example.com"], OutcomeSuccess)

	view, err := svc.ConfirmIssuance("o1", "iss-1")
	if err != nil || view.Status != OrderStatusIssued || view.IssuanceID != "iss-1" {
		t.Fatalf("confirm: %v %+v", err, view)
	}
	outbox := svc.ListOutbox()
	if len(outbox) != 1 || outbox[0].Status != OutboxStatusDone {
		t.Fatalf("outbox should be done, got %+v", outbox)
	}

	// 幂等确认：同 issuanceID 稳定返回，不同 issuanceID 报冲突。
	if _, err := svc.ConfirmIssuance("o1", "iss-1"); err != nil {
		t.Fatalf("repeat confirm should be idempotent: %v", err)
	}
	_, err = svc.ConfirmIssuance("o1", "iss-2")
	requireKind(t, err, KindConflict)
}

func TestCallbacksAfterIssuedReturnStableResults(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	res := mustCreate(t, svc, "o1", []string{"a.example.com"}, time.Hour)
	secret := res.Secrets["a.example.com"]

	mustCallback(t, svc, "o1", "a.example.com", "cb-1", secret, OutcomeSuccess)
	if _, err := svc.ConfirmIssuance("o1", "iss-1"); err != nil {
		t.Fatalf("confirm: %v", err)
	}

	// 已签发后重复回调：复用原结果，稳定。
	replay := mustCallback(t, svc, "o1", "a.example.com", "cb-1", secret, OutcomeSuccess)
	if !replay.Reused || replay.OrderStatus != OrderStatusPendingIssuance {
		t.Fatalf("replay after issuance must return stored result, got %+v", replay)
	}

	// 已签发后新回调号：状态错误，且不影响订单。
	_, err := svc.HandleCallback(CallbackInput{
		OrderID: "o1", Domain: "a.example.com", CallbackID: "cb-new", Secret: secret, Outcome: OutcomeFailure,
	})
	requireKind(t, err, KindState)
	view, _ := svc.GetOrder("o1")
	if view.Status != OrderStatusIssued {
		t.Fatalf("issued order must be terminal, got %s", view.Status)
	}
}

func TestCancelVsCallbackRaceHasDeterministicOutcome(t *testing.T) {
	for i := 0; i < 20; i++ {
		svc := newTestService(t, newFakeClock())
		res := mustCreate(t, svc, "o1", []string{"a.example.com"}, time.Hour)

		var wg sync.WaitGroup
		var cbErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, cbErr = svc.HandleCallback(CallbackInput{
				OrderID: "o1", Domain: "a.example.com", CallbackID: "cb-1",
				Secret: res.Secrets["a.example.com"], Outcome: OutcomeSuccess,
			})
		}()
		go func() {
			defer wg.Done()
			_, _ = svc.CancelOrder("o1")
		}()
		wg.Wait()

		view, _ := svc.GetOrder("o1")
		outbox := svc.ListOutbox()
		switch view.Status {
		case OrderStatusCancelled:
			// 取消赢（或取消在待签发后到达）：终态取消，outbox 不能处于待签发。
			for _, m := range outbox {
				if m.Status == OutboxStatusPending {
					t.Fatalf("cancelled order has live outbox: %+v", m)
				}
			}
		case OrderStatusPendingIssuance:
			// 回调赢且取消未生效不可能：取消在 pending_issuance 上必然成功。
			t.Fatalf("cancel must win over pending_issuance (cbErr=%v)", cbErr)
		default:
			t.Fatalf("unexpected final state %s (cbErr=%v)", view.Status, cbErr)
		}
	}
}

func TestFilePersisterRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	clock := newFakeClock()
	key := []byte("stable-key")

	svc, err := NewService(NewFilePersister(path), WithClock(clock.Now), WithDigestKey(key))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	res := mustCreate(t, svc, "o1", []string{"a.example.com", "b.example.com"}, time.Hour)
	mustCallback(t, svc, "o1", "a.example.com", "cb-1", res.Secrets["a.example.com"], OutcomeSuccess)

	// 模拟重启：同一文件 + 同一摘要密钥恢复服务。
	svc2, err := NewService(NewFilePersister(path), WithClock(clock.Now), WithDigestKey(key))
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	view, err := svc2.GetOrder("o1")
	if err != nil {
		t.Fatalf("GetOrder after reload: %v", err)
	}
	if view.Status != OrderStatusActive || view.Challenges[0].Status != ChallengeStatusSucceeded {
		t.Fatalf("state not persisted: %+v", view)
	}

	// 重启后回调可继续推进并完成签发流程。
	r := mustCallback(t, svc2, "o1", "b.example.com", "cb-2", res.Secrets["b.example.com"], OutcomeSuccess)
	if r.OrderStatus != OrderStatusPendingIssuance {
		t.Fatalf("expected pending_issuance after reload, got %s", r.OrderStatus)
	}
	if n := len(svc2.ListOutbox()); n != 1 {
		t.Fatalf("expected one outbox after reload, got %d", n)
	}
}
