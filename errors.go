package certificaterenewal

import "fmt"

// Kind 对错误进行分类，调用方可以据此做重试、告警或映射到传输层状态码。
type Kind int

const (
	// KindNone 表示没有错误。
	KindNone Kind = iota
	// KindNotFound 表示订单或挑战不存在。
	KindNotFound
	// KindAuth 表示认证失败，例如挑战秘密不匹配。
	KindAuth
	// KindExpired 表示订单已超过截止时间。
	KindExpired
	// KindState 表示当前状态不允许该操作（状态机冲突）。
	KindState
	// KindIdempotency 表示幂等冲突：同一回调号携带了不同的内容。
	KindIdempotency
	// KindInvalid 表示请求参数不合法。
	KindInvalid
)

// String 返回错误类别的可读名称。
func (k Kind) String() string {
	switch k {
	case KindNotFound:
		return "not_found"
	case KindAuth:
		return "auth"
	case KindExpired:
		return "expired"
	case KindState:
		return "state"
	case KindIdempotency:
		return "idempotency"
	case KindInvalid:
		return "invalid"
	default:
		return "none"
	}
}

// Error 是服务返回的统一错误类型，携带分类信息。
type Error struct {
	Kind Kind
	Op   string // 出错的操作，例如 "HandleChallengeCallback"
	Msg  string
}

// Error 实现 error 接口。
func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s: %s", e.Op, e.Kind, e.Msg)
}

// IsKind 判断 err 是否属于指定类别的错误。
func IsKind(err error, k Kind) bool {
	e, ok := err.(*Error)
	return ok && e.Kind == k
}

func newError(k Kind, op, format string, args ...any) *Error {
	return &Error{Kind: k, Op: op, Msg: fmt.Sprintf(format, args...)}
}
