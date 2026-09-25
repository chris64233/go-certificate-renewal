package certificaterenewal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"
)

// Service 管理证书续期订单、域名挑战与签发 outbox。
// 所有状态变更都在同一把互斥锁内完成“检查 + 迁移 + 持久化”，
// 因此取消、过期、签发确认与并发回调之间的竞争结果是确定的。
type Service struct {
	mu        sync.Mutex
	data      *snapshot
	persister Persister
	now       func() time.Time
	digestKey []byte
}

// Option 自定义 Service 行为。
type Option func(*Service)

// WithClock 注入时钟，便于测试过期推进。
func WithClock(now func() time.Time) Option {
	return func(s *Service) { s.now = now }
}

// WithDigestKey 设置挑战秘密摘要的 HMAC 密钥。
// 使用 FilePersister 跨进程重启时必须提供稳定的密钥，否则历史挑战无法校验。
func WithDigestKey(key []byte) Option {
	return func(s *Service) { s.digestKey = slices.Clone(key) }
}

// NewService 从 persister 恢复状态并构造服务；persister 为 nil 时使用内存实现。
func NewService(p Persister, opts ...Option) (*Service, error) {
	if p == nil {
		p = NewMemoryPersister()
	}
	snap, err := p.Load()
	if err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}
	if snap == nil {
		snap = newSnapshot()
	}
	s := &Service{data: snap, persister: p, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	if len(s.digestKey) == 0 {
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, fmt.Errorf("generate digest key: %w", err)
		}
		s.digestKey = key
	}
	return s, nil
}

// CreateOrderInput 创建订单的入参。
type CreateOrderInput struct {
	// OrderID 由调用方提供以支持幂等创建；为空时由服务生成。
	OrderID string
	// Domains 域名集合，创建后冻结。空集合或重复域名会被拒绝。
	Domains []string
	// TTL 订单有效期，截止时间为创建时刻 + TTL，创建后冻结。
	TTL time.Duration
}

// CreateOrderResult 创建订单的结果。
type CreateOrderResult struct {
	Order OrderView
	// Secrets 域名 -> 挑战秘密明文，仅首次创建时返回一次，服务只持久化摘要。
	Secrets map[string]string
	// Reused 为 true 表示命中幂等创建，返回的是已存在的订单（不含秘密明文）。
	Reused bool
}

// CreateOrder 创建订单：冻结域名集合与截止时间，并为每个域名生成独立挑战。
func (s *Service) CreateOrder(in CreateOrderInput) (*CreateOrderResult, error) {
	domains, err := normalizeDomains(in.Domains)
	if err != nil {
		return nil, err
	}
	if in.TTL <= 0 {
		return nil, newError(KindValidation, "ttl must be positive")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	deadline := now.Add(in.TTL)

	if in.OrderID != "" {
		if existing := s.data.Orders[in.OrderID]; existing != nil {
			if slices.Equal(existing.Domains, domains) && existing.Deadline.Equal(deadline) {
				return &CreateOrderResult{Order: orderView(existing), Reused: true}, nil
			}
			return nil, newError(KindConflict, "order %q already exists with different domains or deadline", in.OrderID)
		}
	}

	id := in.OrderID
	if id == "" {
		if id, err = randomID("ord"); err != nil {
			return nil, err
		}
	}

	order := &Order{
		ID:         id,
		Domains:    domains,
		Status:     OrderStatusActive,
		Deadline:   deadline,
		CreatedAt:  now,
		UpdatedAt:  now,
		Challenges: make(map[string]*Challenge, len(domains)),
	}
	secrets := make(map[string]string, len(domains))
	for _, d := range domains {
		secret, err := randomSecret()
		if err != nil {
			return nil, err
		}
		secrets[d] = secret
		order.Challenges[d] = &Challenge{
			Domain:       d,
			Status:       ChallengeStatusPending,
			SecretDigest: s.digestSecret(id, d, secret),
		}
	}
	s.data.Orders[id] = order
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return &CreateOrderResult{Order: orderView(order), Secrets: secrets}, nil
}

// Outcome 是挑战回调的结果。
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
)

// CallbackInput 挑战回调入参。CallbackID 是幂等号：
// 同号同内容复用原结果，同号异内容报 KindConflict。
type CallbackInput struct {
	OrderID    string
	Domain     string
	CallbackID string
	Secret     string
	Outcome    Outcome
	Detail     string
}

// CallbackResult 回调处理结果。
type CallbackResult struct {
	// Reused 为 true 表示该回调号已处理过，本次复用原结果。
	Reused          bool
	ChallengeStatus ChallengeStatus
	OrderStatus     OrderStatus
}

// HandleCallback 处理挑战回调。允许重复、乱序、迟到：
//   - 已处理过的回调号：内容一致复用原结果，内容不同报冲突；
//   - 秘密摘要不匹配报 KindAuth；
//   - 订单已取消/过期/签发时，回调不改变任何状态（迟到回调不能复活订单）；
//   - 单个域名失败只影响该域名；
//   - 订单仍有效且全部域名成功时，原子转为待签发并写出唯一一条 outbox。
func (s *Service) HandleCallback(in CallbackInput) (*CallbackResult, error) {
	if in.OrderID == "" || in.CallbackID == "" {
		return nil, newError(KindValidation, "order id and callback id are required")
	}
	switch in.Outcome {
	case OutcomeSuccess, OutcomeFailure:
	default:
		return nil, newError(KindValidation, "unknown outcome %q", in.Outcome)
	}
	domain := normalizeDomain(in.Domain)
	if domain == "" {
		return nil, newError(KindValidation, "domain is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	order := s.data.Orders[in.OrderID]
	if order == nil {
		return nil, newError(KindNotFound, "order %q not found", in.OrderID)
	}

	// 幂等检查优先于一切状态判断：即使订单已签发，重复回调也返回稳定结果。
	contentHash := hashContent(in.OrderID, domain, in.Secret, string(in.Outcome), in.Detail)
	if recs := s.data.Callbacks[in.OrderID]; recs != nil {
		if rec, ok := recs[in.CallbackID]; ok {
			if rec.ContentHash != contentHash {
				return nil, newError(KindConflict, "callback %q already processed with different content", in.CallbackID)
			}
			return &CallbackResult{Reused: true, ChallengeStatus: rec.ChallengeStatus, OrderStatus: rec.OrderStatus}, nil
		}
	}

	ch := order.Challenges[domain]
	if ch == nil {
		return nil, newError(KindNotFound, "domain %q is not part of order %q", domain, in.OrderID)
	}
	if s.digestSecret(order.ID, domain, in.Secret) != ch.SecretDigest {
		return nil, newError(KindAuth, "invalid challenge secret for domain %q", domain)
	}

	now := s.now()
	if s.expireIfDueLocked(order, now) {
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
	}
	switch order.Status {
	case OrderStatusExpired:
		return nil, newError(KindExpired, "order %q expired at %s", order.ID, order.Deadline.Format(time.RFC3339))
	case OrderStatusCancelled:
		return nil, newError(KindState, "order %q is cancelled", order.ID)
	case OrderStatusPendingIssuance, OrderStatusIssued:
		return nil, newError(KindState, "order %q is already finalized (%s)", order.ID, order.Status)
	}
	if ch.Status != ChallengeStatusPending {
		return nil, newError(KindState, "challenge for domain %q is already %s", domain, ch.Status)
	}

	switch in.Outcome {
	case OutcomeSuccess:
		ch.Status = ChallengeStatusSucceeded
	case OutcomeFailure:
		ch.Status = ChallengeStatusFailed
		ch.FailureReason = in.Detail
	}
	ch.CompletedAt = &now
	order.UpdatedAt = now

	// 全部域名成功 -> 原子转为待签发并写出唯一一条 outbox。
	// 状态迁移与 outbox 写入在同一临界区内，并发到达的最后几个回调不会多发或漏发。
	if allSucceeded(order) {
		order.Status = OrderStatusPendingIssuance
		s.data.Outbox = append(s.data.Outbox, &OutboxMessage{
			ID:        "outbox-" + order.ID,
			OrderID:   order.ID,
			Domains:   slices.Clone(order.Domains),
			Status:    OutboxStatusPending,
			CreatedAt: now,
		})
	}

	if s.data.Callbacks[order.ID] == nil {
		s.data.Callbacks[order.ID] = make(map[string]*CallbackRecord)
	}
	s.data.Callbacks[order.ID][in.CallbackID] = &CallbackRecord{
		CallbackID:      in.CallbackID,
		ContentHash:     contentHash,
		ChallengeStatus: ch.Status,
		OrderStatus:     order.Status,
		ProcessedAt:     now,
	}
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return &CallbackResult{ChallengeStatus: ch.Status, OrderStatus: order.Status}, nil
}

// CancelOrder 取消订单。active / pending_issuance 可取消；
// 重复取消幂等返回当前状态；已过期报 KindExpired，已签发报 KindState。
func (s *Service) CancelOrder(orderID string) (*OrderView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	order := s.data.Orders[orderID]
	if order == nil {
		return nil, newError(KindNotFound, "order %q not found", orderID)
	}
	now := s.now()
	if s.expireIfDueLocked(order, now) {
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
	}
	switch order.Status {
	case OrderStatusActive, OrderStatusPendingIssuance:
		order.Status = OrderStatusCancelled
		order.UpdatedAt = now
		// 已写出的 outbox 一并作废，签发 worker 不会为已取消订单出证。
		for _, msg := range s.data.Outbox {
			if msg.OrderID == order.ID && msg.Status == OutboxStatusPending {
				msg.Status = OutboxStatusCancelled
			}
		}
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
		v := orderView(order)
		return &v, nil
	case OrderStatusCancelled:
		v := orderView(order)
		return &v, nil
	case OrderStatusExpired:
		return nil, newError(KindExpired, "order %q expired at %s", order.ID, order.Deadline.Format(time.RFC3339))
	default:
		return nil, newError(KindState, "order %q is already %s", order.ID, order.Status)
	}
}

// AdvanceExpiry 推进过期：把所有已过截止时间的 active 订单置为 expired。
// 返回本次过期的订单 ID（有序、确定）。
func (s *Service) AdvanceExpiry() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	var expired []string
	for _, o := range s.data.Orders {
		if s.expireIfDueLocked(o, now) {
			expired = append(expired, o.ID)
		}
	}
	if len(expired) > 0 {
		slices.Sort(expired)
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
	}
	return expired, nil
}

// ConfirmIssuance 确认签发完成：pending_issuance -> issued，并办结 outbox。
// 对已签发订单用同一 issuanceID 重复确认是幂等的；换 issuanceID 报冲突。
func (s *Service) ConfirmIssuance(orderID, issuanceID string) (*OrderView, error) {
	if issuanceID == "" {
		return nil, newError(KindValidation, "issuance id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	order := s.data.Orders[orderID]
	if order == nil {
		return nil, newError(KindNotFound, "order %q not found", orderID)
	}
	switch order.Status {
	case OrderStatusPendingIssuance:
		now := s.now()
		order.Status = OrderStatusIssued
		order.IssuanceID = issuanceID
		order.UpdatedAt = now
		for _, msg := range s.data.Outbox {
			if msg.OrderID == order.ID && msg.Status == OutboxStatusPending {
				msg.Status = OutboxStatusDone
			}
		}
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
		v := orderView(order)
		return &v, nil
	case OrderStatusIssued:
		if order.IssuanceID == issuanceID {
			v := orderView(order)
			return &v, nil
		}
		return nil, newError(KindConflict, "order %q already issued with different issuance id", orderID)
	case OrderStatusExpired:
		return nil, newError(KindExpired, "order %q expired at %s", order.ID, order.Deadline.Format(time.RFC3339))
	default:
		return nil, newError(KindState, "order %q is %s, cannot confirm issuance", order.ID, order.Status)
	}
}

// GetOrder 查询订单及其挑战状态（不含秘密摘要）。
func (s *Service) GetOrder(orderID string) (*OrderView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	order := s.data.Orders[orderID]
	if order == nil {
		return nil, newError(KindNotFound, "order %q not found", orderID)
	}
	v := orderView(order)
	return &v, nil
}

// ListOutbox 返回全部 outbox 消息的副本，供签发 worker 轮询。
func (s *Service) ListOutbox() []OutboxMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]OutboxMessage, len(s.data.Outbox))
	for i, msg := range s.data.Outbox {
		cp := *msg
		cp.Domains = slices.Clone(msg.Domains)
		out[i] = cp
	}
	return out
}

// expireIfDueLocked 惰性过期：active 且已过截止时间则置为 expired，返回是否发生迁移。
func (s *Service) expireIfDueLocked(o *Order, now time.Time) bool {
	if o.Status == OrderStatusActive && !now.Before(o.Deadline) {
		o.Status = OrderStatusExpired
		o.UpdatedAt = now
		return true
	}
	return false
}

func (s *Service) persistLocked() error {
	if err := s.persister.Save(s.data); err != nil {
		return fmt.Errorf("persist state: %w", err)
	}
	return nil
}

// digestSecret 计算挑战秘密的 HMAC-SHA256 摘要，绑定订单与域名，只持久化摘要。
func (s *Service) digestSecret(orderID, domain, secret string) string {
	h := hmac.New(sha256.New, s.digestKey)
	io.WriteString(h, orderID)
	h.Write([]byte{0})
	io.WriteString(h, domain)
	h.Write([]byte{0})
	io.WriteString(h, secret)
	return hex.EncodeToString(h.Sum(nil))
}

// hashContent 计算回调内容摘要，用于同号异内容的冲突检测。
func hashContent(orderID, domain, secret, outcome, detail string) string {
	h := sha256.New()
	for _, part := range []string{orderID, domain, secret, outcome, detail} {
		io.WriteString(h, part)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func allSucceeded(o *Order) bool {
	for _, ch := range o.Challenges {
		if ch.Status != ChallengeStatusSucceeded {
			return false
		}
	}
	return true
}

func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSpace(d))
}

func normalizeDomains(domains []string) ([]string, error) {
	if len(domains) == 0 {
		return nil, newError(KindValidation, "at least one domain is required")
	}
	out := make([]string, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		d = normalizeDomain(d)
		if d == "" || strings.ContainsAny(d, " \t\n") {
			return nil, newError(KindValidation, "invalid domain %q", d)
		}
		if _, dup := seen[d]; dup {
			return nil, newError(KindValidation, "duplicate domain %q", d)
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	slices.Sort(out)
	return out, nil
}

func randomID(prefix string) (string, error) {
	b := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return prefix + "-" + hex.EncodeToString(b), nil
}

func randomSecret() (string, error) {
	b := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ChallengeView 是挑战的对外视图，不暴露秘密摘要。
type ChallengeView struct {
	Domain        string
	Status        ChallengeStatus
	FailureReason string
	CompletedAt   *time.Time
}

// OrderView 是订单的对外视图。
type OrderView struct {
	ID         string
	Domains    []string
	Status     OrderStatus
	Deadline   time.Time
	CreatedAt  time.Time
	IssuanceID string
	Challenges []ChallengeView
}

func orderView(o *Order) OrderView {
	v := OrderView{
		ID:         o.ID,
		Domains:    slices.Clone(o.Domains),
		Status:     o.Status,
		Deadline:   o.Deadline,
		CreatedAt:  o.CreatedAt,
		IssuanceID: o.IssuanceID,
		Challenges: make([]ChallengeView, 0, len(o.Challenges)),
	}
	for _, d := range o.Domains {
		ch := o.Challenges[d]
		v.Challenges = append(v.Challenges, ChallengeView{
			Domain:        ch.Domain,
			Status:        ch.Status,
			FailureReason: ch.FailureReason,
			CompletedAt:   ch.CompletedAt,
		})
	}
	return v
}
