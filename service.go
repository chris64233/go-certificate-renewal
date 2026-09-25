package certificaterenewal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Service 提供证书续期订单的核心操作。
//
// 并发模型：所有变更操作都在 mu 下串行执行，因此
// “全部挑战成功 → 原子转为待签发 + 写唯一一条 outbox”
// 以及取消、过期、签发确认之间的竞争都有确定的结果。
type Service struct {
	mu    sync.Mutex
	store Store
	now   func() time.Time
}

// NewService 创建一个服务。now 为时钟，便于测试注入；传 nil 使用真实时钟。
func NewService(store Store, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, now: now}
}

// CreateOrder 创建一笔续期订单：冻结域名集合与截止时间，
// 并为每个域名单独生成挑战。明文秘密只随返回值出现一次，
// 存储中仅保留其 SHA-256 摘要。
func (s *Service) CreateOrder(in CreateOrderInput) (Order, []CreatedChallenge, error) {
	const op = "CreateOrder"
	domains, err := normalizeDomains(in.Domains)
	if err != nil {
		return Order{}, nil, newError(KindInvalid, op, "%s", err)
	}
	now := s.now()
	if !in.Deadline.After(now) {
		return Order{}, nil, newError(KindInvalid, op, "deadline %s must be in the future", in.Deadline)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	order := Order{
		ID:        newID(),
		Domains:   domains,
		Status:    OrderStatusPending,
		Deadline:  in.Deadline,
		CreatedAt: now,
		UpdatedAt: now,
	}
	challenges := make([]Challenge, 0, len(domains))
	created := make([]CreatedChallenge, 0, len(domains))
	for _, d := range domains {
		secret, err := newSecret()
		if err != nil {
			return Order{}, nil, fmt.Errorf("%s: generate secret: %w", op, err)
		}
		c := Challenge{
			ID:           newID(),
			OrderID:      order.ID,
			Domain:       d,
			SecretDigest: digestSecret(secret),
			Status:       ChallengeStatusPending,
			UpdatedAt:    now,
		}
		challenges = append(challenges, c)
		created = append(created, CreatedChallenge{Challenge: c, Secret: secret})
	}
	if err := s.store.InsertOrder(order, challenges); err != nil {
		return Order{}, nil, err
	}
	return order, created, nil
}

// HandleChallengeCallback 处理一次挑战回调。
//
// 幂等规则：以 (订单, 回调号) 为键，回调号与内容都相同则复用首次结果；
// 回调号相同但内容不同则返回 KindIdempotency 冲突。
// 单个域名的失败只影响该挑战本身，不影响其他域名。
// 订单处于终态（已取消/已过期/已签发）时，回调不会复活订单，
// 结果仍会被记录，保证重复回调返回稳定结果。
func (s *Service) HandleChallengeCallback(in CallbackInput) (CallbackResult, error) {
	const op = "HandleChallengeCallback"
	if in.CallbackID == "" {
		return CallbackResult{}, newError(KindInvalid, op, "callback id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	order, err := s.store.GetOrder(in.OrderID)
	if err != nil {
		return CallbackResult{}, err
	}
	contentHash := hashCallbackContent(in)

	// 已处理过的回调：同内容复用结果，异内容报幂等冲突。
	if rec, ok, err := s.store.GetCallback(in.OrderID, in.CallbackID); err != nil {
		return CallbackResult{}, err
	} else if ok {
		if rec.ContentHash != contentHash {
			return CallbackResult{}, newError(KindIdempotency, op,
				"callback %q already processed with different content", in.CallbackID)
		}
		rec.Result.Duplicate = true
		if rec.ErrKind != KindNone {
			return CallbackResult{}, newError(rec.ErrKind, op, "replay of callback %q", in.CallbackID)
		}
		return rec.Result, nil
	}

	now := s.now()
	record := func(res CallbackResult, kind Kind) (CallbackResult, error) {
		rec := CallbackRecord{
			OrderID:     in.OrderID,
			CallbackID:  in.CallbackID,
			ContentHash: contentHash,
			Result:      res,
			ErrKind:     kind,
			CreatedAt:   now,
		}
		if err := s.store.PutCallback(rec); err != nil {
			return CallbackResult{}, err
		}
		if kind != KindNone {
			return CallbackResult{}, newError(kind, op, "callback %q rejected", in.CallbackID)
		}
		return res, nil
	}

	// 惰性过期：到达时已超过截止时间的 PENDING 订单就地转为 EXPIRED，
	// 使回调与过期推进之间的竞争结果确定。
	if order.Status == OrderStatusPending && !now.Before(order.Deadline) {
		order.Status = OrderStatusExpired
		order.UpdatedAt = now
		if err := s.store.UpdateOrder(order); err != nil {
			return CallbackResult{}, err
		}
		return record(CallbackResult{
			OrderID:     in.OrderID,
			Domain:      in.Domain,
			OrderStatus: OrderStatusExpired,
		}, KindExpired)
	}

	// 终态订单：记录回调并返回稳定结果，绝不复活订单。
	switch order.Status {
	case OrderStatusCancelled, OrderStatusExpired:
		return record(CallbackResult{
			OrderID:     in.OrderID,
			Domain:      in.Domain,
			OrderStatus: order.Status,
		}, KindState)
	case OrderStatusIssued, OrderStatusReadyForIssuance:
		// 挑战已全部完成，新回调不再改变任何状态。
		return record(CallbackResult{
			OrderID:         in.OrderID,
			Domain:          in.Domain,
			ChallengeStatus: ChallengeStatusSucceeded,
			OrderStatus:     order.Status,
		}, KindNone)
	}

	challenges, err := s.store.GetChallenges(in.OrderID)
	if err != nil {
		return CallbackResult{}, err
	}
	idx := -1
	for i := range challenges {
		if challenges[i].Domain == in.Domain {
			idx = i
			break
		}
	}
	if idx < 0 {
		return CallbackResult{}, newError(KindNotFound, op,
			"no challenge for domain %q in order %q", in.Domain, in.OrderID)
	}
	ch := challenges[idx]

	// 认证：回调必须携带与冻结摘要匹配的挑战秘密。
	// 认证失败不写入回调记录，避免攻击者占用回调号。
	if digestSecret(in.Secret) != ch.SecretDigest {
		return CallbackResult{}, newError(KindAuth, op,
			"secret mismatch for domain %q", in.Domain)
	}

	// 挑战结果先到先定，后续不同回调号的回调不再推翻已有结论。
	if ch.Status != ChallengeStatusPending {
		return record(CallbackResult{
			OrderID:         in.OrderID,
			Domain:          in.Domain,
			ChallengeStatus: ch.Status,
			OrderStatus:     order.Status,
		}, KindState)
	}

	if in.Succeeded {
		ch.Status = ChallengeStatusSucceeded
	} else {
		ch.Status = ChallengeStatusFailed
		ch.FailureReason = in.FailureReason
	}
	ch.UpdatedAt = now
	if err := s.store.UpdateChallenge(ch); err != nil {
		return CallbackResult{}, err
	}

	// 全部挑战成功时，原子地将订单转为待签发并写出唯一一条 outbox。
	if ch.Status == ChallengeStatusSucceeded && allSucceeded(challenges, ch) {
		order.Status = OrderStatusReadyForIssuance
		order.UpdatedAt = now
		if err := s.store.UpdateOrder(order); err != nil {
			return CallbackResult{}, err
		}
		msg := OutboxMessage{
			ID:        newID(),
			OrderID:   order.ID,
			Type:      TypeIssuanceRequested,
			CreatedAt: now,
		}
		if err := s.store.AppendOutbox(msg); err != nil {
			return CallbackResult{}, err
		}
	}

	return record(CallbackResult{
		OrderID:         in.OrderID,
		Domain:          in.Domain,
		ChallengeStatus: ch.Status,
		OrderStatus:     order.Status,
	}, KindNone)
}

// CancelOrder 取消订单。PENDING 与 READY_FOR_ISSUANCE 可取消；
// 重复取消返回稳定结果；已过期或已签发的订单不可取消。
func (s *Service) CancelOrder(orderID string) (Order, error) {
	const op = "CancelOrder"
	s.mu.Lock()
	defer s.mu.Unlock()

	order, err := s.store.GetOrder(orderID)
	if err != nil {
		return Order{}, err
	}
	switch order.Status {
	case OrderStatusCancelled:
		return order, nil // 幂等：重复取消返回稳定结果
	case OrderStatusExpired:
		return Order{}, newError(KindState, op, "order %q already expired", orderID)
	case OrderStatusIssued:
		return Order{}, newError(KindState, op, "order %q already issued", orderID)
	}
	now := s.now()
	// 与过期竞争时，截止时间先到者胜。
	if order.Status == OrderStatusPending && !now.Before(order.Deadline) {
		order.Status = OrderStatusExpired
		order.UpdatedAt = now
		if err := s.store.UpdateOrder(order); err != nil {
			return Order{}, err
		}
		return Order{}, newError(KindExpired, op, "order %q expired at %s", orderID, order.Deadline)
	}
	order.Status = OrderStatusCancelled
	order.UpdatedAt = now
	if err := s.store.UpdateOrder(order); err != nil {
		return Order{}, err
	}
	return order, nil
}

// AdvanceExpiry 推进过期：把所有已超过截止时间的 PENDING 订单转为 EXPIRED。
// 返回本次被置为过期的订单 ID。
func (s *Service) AdvanceExpiry() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	orders, err := s.store.ListOrders()
	if err != nil {
		return nil, err
	}
	now := s.now()
	var expired []string
	for _, o := range orders {
		if o.Status != OrderStatusPending || now.Before(o.Deadline) {
			continue
		}
		o.Status = OrderStatusExpired
		o.UpdatedAt = now
		if err := s.store.UpdateOrder(o); err != nil {
			return nil, err
		}
		expired = append(expired, o.ID)
	}
	sort.Strings(expired)
	return expired, nil
}

// ConfirmIssuance 确认签发完成：READY_FOR_ISSUANCE → ISSUED。
// 重复确认返回稳定结果；已取消或已过期的订单返回状态错误。
func (s *Service) ConfirmIssuance(orderID string) (Order, error) {
	const op = "ConfirmIssuance"
	s.mu.Lock()
	defer s.mu.Unlock()

	order, err := s.store.GetOrder(orderID)
	if err != nil {
		return Order{}, err
	}
	switch order.Status {
	case OrderStatusIssued:
		return order, nil // 幂等：重复确认返回稳定结果
	case OrderStatusReadyForIssuance:
		order.Status = OrderStatusIssued
		order.UpdatedAt = s.now()
		if err := s.store.UpdateOrder(order); err != nil {
			return Order{}, err
		}
		return order, nil
	default:
		return Order{}, newError(KindState, op,
			"order %q in status %s cannot be issued", orderID, order.Status)
	}
}

// GetOrder 查询订单及其全部挑战。
func (s *Service) GetOrder(orderID string) (OrderView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	order, err := s.store.GetOrder(orderID)
	if err != nil {
		return OrderView{}, err
	}
	challenges, err := s.store.GetChallenges(orderID)
	if err != nil {
		return OrderView{}, err
	}
	return OrderView{Order: order, Challenges: challenges}, nil
}

// ListOutbox 返回 outbox 中的全部消息，供签发消费者拉取。
func (s *Service) ListOutbox() ([]OutboxMessage, error) {
	return s.store.ListOutbox()
}

// normalizeDomains 去重、排序并校验域名集合，保证创建时冻结的集合确定。
func normalizeDomains(domains []string) ([]string, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("at least one domain is required")
	}
	seen := make(map[string]struct{}, len(domains))
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		if d == "" {
			return nil, fmt.Errorf("domain must not be empty")
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}

// allSucceeded 判断除 ch 之外的挑战是否都已成功（ch 刚被置为成功）。
func allSucceeded(challenges []Challenge, ch Challenge) bool {
	for _, c := range challenges {
		if c.ID == ch.ID {
			continue
		}
		if c.Status != ChallengeStatusSucceeded {
			return false
		}
	}
	return true
}

// digestSecret 计算挑战秘密的安全摘要，存储中只保留该摘要。
func digestSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// hashCallbackContent 计算回调内容摘要，用于识别“同号异内容”的幂等冲突。
func hashCallbackContent(in CallbackInput) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%t\x00%s", in.Domain, in.Secret, in.Succeeded, in.FailureReason)
	return hex.EncodeToString(h.Sum(nil))
}

// newID 生成随机十六进制 ID。
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// newSecret 生成挑战秘密明文。
func newSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
