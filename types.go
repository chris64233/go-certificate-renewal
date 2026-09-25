package certificaterenewal

import "time"

// OrderStatus 描述证书续期订单的生命周期状态。
//
// 状态机：
//
//	PENDING --(全部挑战成功)--> READY_FOR_ISSUANCE --(签发确认)--> ISSUED
//	PENDING --(取消)--> CANCELLED
//	PENDING --(超过截止时间)--> EXPIRED
//	READY_FOR_ISSUANCE --(取消)--> CANCELLED
//
// CANCELLED、EXPIRED、ISSUED 均为终态，任何回调都不能使订单离开终态。
type OrderStatus string

const (
	OrderStatusPending          OrderStatus = "PENDING"
	OrderStatusReadyForIssuance OrderStatus = "READY_FOR_ISSUANCE"
	OrderStatusIssued           OrderStatus = "ISSUED"
	OrderStatusCancelled        OrderStatus = "CANCELLED"
	OrderStatusExpired          OrderStatus = "EXPIRED"
)

// Terminal 报告订单状态是否为终态。
func (s OrderStatus) Terminal() bool {
	switch s {
	case OrderStatusIssued, OrderStatusCancelled, OrderStatusExpired:
		return true
	default:
		return false
	}
}

// ChallengeStatus 描述单个域名挑战的状态。
type ChallengeStatus string

const (
	ChallengeStatusPending   ChallengeStatus = "PENDING"
	ChallengeStatusSucceeded ChallengeStatus = "SUCCEEDED"
	ChallengeStatusFailed    ChallengeStatus = "FAILED"
)

// Order 是一笔聚合多域名的证书续期订单。
// 域名集合与截止时间在创建时冻结，之后不可修改。
type Order struct {
	ID        string
	Domains   []string
	Status    OrderStatus
	Deadline  time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Challenge 是订单下某个域名的挑战。
// 挑战秘密只持久化安全摘要（SHA-256），明文秘密仅在创建时返回给调用方一次。
type Challenge struct {
	ID            string
	OrderID       string
	Domain        string
	SecretDigest  string // 十六进制编码的 SHA-256 摘要
	Status        ChallengeStatus
	FailureReason string
	UpdatedAt     time.Time
}

// OutboxMessage 是签发 outbox 中的一条消息。
// 每笔订单最多产生一条 TypeIssuanceRequested 消息，
// 由订单从 PENDING 原子转为 READY_FOR_ISSUANCE 时写入。
type OutboxMessage struct {
	ID        string
	OrderID   string
	Type      string
	CreatedAt time.Time
}

// TypeIssuanceRequested 是请求签发证书的 outbox 消息类型。
const TypeIssuanceRequested = "issuance.requested"

// CallbackRecord 记录一条已处理回调的判定结果，用于幂等复用。
// 以 (OrderID, CallbackID) 为键：回调号与内容都相同则复用原结果，
// 回调号相同但内容不同则报幂等冲突。
type CallbackRecord struct {
	OrderID     string
	CallbackID  string
	ContentHash string // 回调内容的 SHA-256 摘要
	Result      CallbackResult
	ErrKind     Kind // 非 KindNone 时，重放应返回同类错误
	CreatedAt   time.Time
}

// CreateOrderInput 是创建订单的入参。
type CreateOrderInput struct {
	Domains  []string
	Deadline time.Time
}

// CreatedChallenge 是创建订单时返回的挑战信息，包含仅此一次可见的明文秘密。
type CreatedChallenge struct {
	Challenge Challenge
	Secret    string // 明文秘密，不会持久化
}

// CallbackInput 是一次挑战回调的入参。
type CallbackInput struct {
	OrderID       string
	Domain        string
	CallbackID    string // 回调号，用于幂等
	Secret        string // 挑战秘密明文，用于认证
	Succeeded     bool
	FailureReason string
}

// CallbackResult 是一次回调的处理结果。重复回调返回与首次完全一致的结果。
type CallbackResult struct {
	OrderID         string
	Domain          string
	ChallengeStatus ChallengeStatus
	OrderStatus     OrderStatus
	Duplicate       bool // true 表示该结果复用自首次处理的记录
}

// OrderView 是订单查询结果，包含订单及其全部挑战。
type OrderView struct {
	Order      Order
	Challenges []Challenge
}
