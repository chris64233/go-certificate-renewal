package certificaterenewal

import "sync"

// Store 是订单、挑战、回调记录与 outbox 的持久化接口。
// 实现方需要保证单次调用的原子性；跨实体的原子性由 Service 层串行化保证，
// 替换为数据库实现时应改用事务。
type Store interface {
	InsertOrder(order Order, challenges []Challenge) error
	GetOrder(id string) (Order, error)
	UpdateOrder(order Order) error
	ListOrders() ([]Order, error)

	GetChallenges(orderID string) ([]Challenge, error)
	UpdateChallenge(c Challenge) error

	GetCallback(orderID, callbackID string) (CallbackRecord, bool, error)
	PutCallback(rec CallbackRecord) error

	AppendOutbox(msg OutboxMessage) error
	ListOutbox() ([]OutboxMessage, error)
}

// InMemoryStore 是 Store 的内存实现，返回的数据均为深拷贝，可安全并发使用。
type InMemoryStore struct {
	mu         sync.RWMutex
	orders     map[string]Order
	challenges map[string][]Challenge    // orderID -> challenges
	callbacks  map[string]CallbackRecord // orderID+"/"+callbackID -> record
	outbox     []OutboxMessage
}

// NewInMemoryStore 创建一个空的内存存储。
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		orders:     make(map[string]Order),
		challenges: make(map[string][]Challenge),
		callbacks:  make(map[string]CallbackRecord),
	}
}

func cloneOrder(o Order) Order {
	o.Domains = append([]string(nil), o.Domains...)
	return o
}

func cloneChallenges(cs []Challenge) []Challenge {
	return append([]Challenge(nil), cs...)
}

// InsertOrder 持久化新订单及其挑战。
func (s *InMemoryStore) InsertOrder(order Order, challenges []Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orders[order.ID] = cloneOrder(order)
	s.challenges[order.ID] = cloneChallenges(challenges)
	return nil
}

// GetOrder 返回订单的拷贝。
func (s *InMemoryStore) GetOrder(id string) (Order, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.orders[id]
	if !ok {
		return Order{}, newError(KindNotFound, "Store.GetOrder", "order %q not found", id)
	}
	return cloneOrder(o), nil
}

// UpdateOrder 覆盖已有订单。
func (s *InMemoryStore) UpdateOrder(order Order) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orders[order.ID]; !ok {
		return newError(KindNotFound, "Store.UpdateOrder", "order %q not found", order.ID)
	}
	s.orders[order.ID] = cloneOrder(order)
	return nil
}

// ListOrders 返回全部订单的拷贝。
func (s *InMemoryStore) ListOrders() ([]Order, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Order, 0, len(s.orders))
	for _, o := range s.orders {
		out = append(out, cloneOrder(o))
	}
	return out, nil
}

// GetChallenges 返回订单全部挑战的拷贝。
func (s *InMemoryStore) GetChallenges(orderID string) ([]Challenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cs, ok := s.challenges[orderID]
	if !ok {
		return nil, newError(KindNotFound, "Store.GetChallenges", "order %q not found", orderID)
	}
	return cloneChallenges(cs), nil
}

// UpdateChallenge 覆盖已有挑战。
func (s *InMemoryStore) UpdateChallenge(c Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, ok := s.challenges[c.OrderID]
	if !ok {
		return newError(KindNotFound, "Store.UpdateChallenge", "order %q not found", c.OrderID)
	}
	for i := range cs {
		if cs[i].ID == c.ID {
			cs[i] = c
			return nil
		}
	}
	return newError(KindNotFound, "Store.UpdateChallenge", "challenge %q not found", c.ID)
}

// GetCallback 查询已处理的回调记录。
func (s *InMemoryStore) GetCallback(orderID, callbackID string) (CallbackRecord, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.callbacks[orderID+"/"+callbackID]
	return rec, ok, nil
}

// PutCallback 持久化回调处理记录。
func (s *InMemoryStore) PutCallback(rec CallbackRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.callbacks[rec.OrderID+"/"+rec.CallbackID] = rec
	return nil
}

// AppendOutbox 追加一条 outbox 消息。
func (s *InMemoryStore) AppendOutbox(msg OutboxMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outbox = append(s.outbox, msg)
	return nil
}

// ListOutbox 返回全部 outbox 消息的拷贝。
func (s *InMemoryStore) ListOutbox() ([]OutboxMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]OutboxMessage(nil), s.outbox...), nil
}
