package certificaterenewal

import (
	"errors"
	"fmt"
)

// Kind 区分错误的类别，调用方可以据此决定重试、告警或直接失败。
type Kind string

const (
	// KindNotFound 订单或域名挑战不存在。
	KindNotFound Kind = "not_found"
	// KindAuth 挑战秘密校验失败。
	KindAuth Kind = "auth"
	// KindExpired 订单已超过冻结的截止时间。
	KindExpired Kind = "expired"
	// KindState 当前状态不允许该操作（如重复完成挑战、取消已签发订单）。
	KindState Kind = "state"
	// KindConflict 幂等冲突：同一幂等号携带了不同的内容。
	KindConflict Kind = "conflict"
	// KindValidation 请求参数不合法。
	KindValidation Kind = "validation"
)

// Error 是服务返回的业务错误，携带分类信息。
type Error struct {
	Kind    Kind
	Message string
}

func (e *Error) Error() string { return string(e.Kind) + ": " + e.Message }

// KindOf 提取错误的类别；ok 为 false 表示不是本服务定义的业务错误。
func KindOf(err error) (kind Kind, ok bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind, true
	}
	return "", false
}

func newError(k Kind, format string, args ...any) *Error {
	return &Error{Kind: k, Message: fmt.Sprintf(format, args...)}
}
