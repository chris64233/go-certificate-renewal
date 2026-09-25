package certificaterenewal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// snapshot 是服务的全部持久化状态。
type snapshot struct {
	Orders    map[string]*Order                     `json:"orders"`
	Callbacks map[string]map[string]*CallbackRecord `json:"callbacks"`
	Outbox    []*OutboxMessage                      `json:"outbox"`
}

func newSnapshot() *snapshot {
	return &snapshot{
		Orders:    make(map[string]*Order),
		Callbacks: make(map[string]map[string]*CallbackRecord),
	}
}

// cloneSnapshot 通过 JSON 往返做深拷贝，避免内存态与持久化态互相引用。
func cloneSnapshot(s *snapshot) (*snapshot, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var out snapshot
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Persister 负责持久化快照。Save 与 Load 均传递深拷贝，
// 实现方不需要关心调用方后续的内存修改。
type Persister interface {
	Load() (*snapshot, error)
	Save(s *snapshot) error
}

// MemoryPersister 进程内持久化，主要用于测试。
type MemoryPersister struct {
	mu   sync.Mutex
	snap *snapshot
}

func NewMemoryPersister() *MemoryPersister { return &MemoryPersister{} }

func (m *MemoryPersister) Load() (*snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.snap == nil {
		return nil, nil
	}
	return cloneSnapshot(m.snap)
}

func (m *MemoryPersister) Save(s *snapshot) error {
	cloned, err := cloneSnapshot(s)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.snap = cloned
	m.mu.Unlock()
	return nil
}

// FilePersister 将快照以 JSON 形式落盘，写临时文件后原子 rename。
type FilePersister struct {
	path string
	mu   sync.Mutex
}

func NewFilePersister(path string) *FilePersister { return &FilePersister{path: path} }

func (f *FilePersister) Load() (*snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	var snap snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	return &snap, nil
}

func (f *FilePersister) Save(s *snapshot) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write snapshot: %w", err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		return fmt.Errorf("commit snapshot: %w", err)
	}
	if dir := filepath.Dir(f.path); dir != "" {
		if d, err := os.Open(dir); err == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}
	return nil
}
