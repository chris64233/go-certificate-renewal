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

// ActivationStage 描述证书版本的分阶段激活进度。
//
//	pending -> canary -> partial -> full
//
// 阶段只能前进不能后退；每个阶段激活服务范围的一个确定性前缀子集，
// 进入 full 时证书覆盖其全部服务范围。
type ActivationStage string

const (
	StagePending ActivationStage = "pending"
	StageCanary  ActivationStage = "canary"
	StagePartial ActivationStage = "partial"
	StageFull    ActivationStage = "full"
)

// stageLevel 返回阶段的推进序号，pending 为 0，full 为 3。
func stageLevel(s ActivationStage) int {
	switch s {
	case StageCanary:
		return 1
	case StagePartial:
		return 2
	case StageFull:
		return 3
	default:
		return 0
	}
}

// Certificate 是一个证书版本。域名与服务范围在注册时冻结；
// Seq 是单调递增的版本序号，用于判定新旧，保证旧版本不能重新成为当前证书。
type Certificate struct {
	ID           string          `json:"id"`
	Domain       string          `json:"domain"`
	Scopes       []string        `json:"scopes"`
	Stage        ActivationStage `json:"stage"`
	Seq          uint64          `json:"seq"`
	NotAfter     time.Time       `json:"not_after"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
	RevokedAt    *time.Time      `json:"revoked_at,omitempty"`
	RevocationID string          `json:"revocation_id,omitempty"`
}

// Revoked 报告证书是否已被撤销。
func (c *Certificate) Revoked() bool { return c.RevokedAt != nil }

// Revocation 是一条撤销记录，保存证书、域名、撤销时的激活阶段与服务范围。
// RevocationID 是幂等号：同号同内容复用原结果，同号异内容报冲突。
type Revocation struct {
	ID          string          `json:"id"`
	CertID      string          `json:"cert_id"`
	Domain      string          `json:"domain"`
	Stage       ActivationStage `json:"stage"`
	Scopes      []string        `json:"scopes"`
	ContentHash string          `json:"content_hash"`
	CreatedAt   time.Time       `json:"created_at"`
}
