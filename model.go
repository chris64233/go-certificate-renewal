package certificaterenewal

import "time"

// OrderStatus 描述订单的生命周期。
//
//	active --(全部挑战成功)--> pending_issuance --(签发确认)--> issued
//	active --(取消/过期)--> cancelled / expired
//	pending_issuance --(取消)--> cancelled
//
// cancelled、expired、issued 均为终态，任何回调都不能让订单复活。
type OrderStatus string

const (
	OrderStatusActive          OrderStatus = "active"
	OrderStatusPendingIssuance OrderStatus = "pending_issuance"
	OrderStatusIssued          OrderStatus = "issued"
	OrderStatusCancelled       OrderStatus = "cancelled"
	OrderStatusExpired         OrderStatus = "expired"
)

// ChallengeStatus 描述单个域名挑战的状态，域名之间互不影响。
type ChallengeStatus string

const (
	ChallengeStatusPending   ChallengeStatus = "pending"
	ChallengeStatusSucceeded ChallengeStatus = "succeeded"
	ChallengeStatusFailed    ChallengeStatus = "failed"
)

// Challenge 是单个域名的挑战记录。秘密只保存 HMAC 摘要，不明文持久化。
type Challenge struct {
	Domain        string          `json:"domain"`
	Status        ChallengeStatus `json:"status"`
	SecretDigest  string          `json:"secret_digest"`
	FailureReason string          `json:"failure_reason,omitempty"`
	CompletedAt   *time.Time      `json:"completed_at,omitempty"`
}

// Order 是续期订单。域名集合与截止时间在创建时冻结，之后不可修改。
type Order struct {
	ID         string                `json:"id"`
	Domains    []string              `json:"domains"`
	Status     OrderStatus           `json:"status"`
	Deadline   time.Time             `json:"deadline"`
	CreatedAt  time.Time             `json:"created_at"`
	UpdatedAt  time.Time             `json:"updated_at"`
	Challenges map[string]*Challenge `json:"challenges"`
	IssuanceID string                `json:"issuance_id,omitempty"`
}

// OutboxStatus 描述签发 outbox 消息的状态。
type OutboxStatus string

const (
	OutboxStatusPending   OutboxStatus = "pending"
	OutboxStatusDone      OutboxStatus = "done"
	OutboxStatusCancelled OutboxStatus = "cancelled"
)

// OutboxMessage 是签发 outbox 消息。每个订单最多写出一条，
// 与订单进入 pending_issuance 在同一临界区内完成，保证不重不漏。
type OutboxMessage struct {
	ID        string       `json:"id"`
	OrderID   string       `json:"order_id"`
	Domains   []string     `json:"domains"`
	Status    OutboxStatus `json:"status"`
	CreatedAt time.Time    `json:"created_at"`
}

// CallbackRecord 记录已处理回调的幂等信息：
// 同一回调号 + 相同内容复用原结果，相同回调号 + 不同内容报冲突。
type CallbackRecord struct {
	CallbackID      string          `json:"callback_id"`
	ContentHash     string          `json:"content_hash"`
	ChallengeStatus ChallengeStatus `json:"challenge_status"`
	OrderStatus     OrderStatus     `json:"order_status"`
	ProcessedAt     time.Time       `json:"processed_at"`
}
