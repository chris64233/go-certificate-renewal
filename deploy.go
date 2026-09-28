package certificaterenewal

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
)

// CertVersionStatus 描述证书版本的生命周期。
//
//	staged --(部署计划全部节点完成)--> current --(被新版本取代)--> pending_retirement
//
// staged 表示签发确认后生成的不可变版本，尚未替换当前证书；
// pending_retirement 表示已被取代、等待退役，不会被直接删除。
type CertVersionStatus string

const (
	CertVersionStaged            CertVersionStatus = "staged"
	CertVersionCurrent           CertVersionStatus = "current"
	CertVersionPendingRetirement CertVersionStatus = "pending_retirement"
)

// CertMaterial 是证书的秘密材料，只在签发确认时写入、节点领取时返回，
// 任何普通查询视图都不携带它。
type CertMaterial struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// CertVersion 是签发确认后生成的不可变证书版本。创建后内容不再修改，
// 只有 Status 随部署计划推进而迁移。
type CertVersion struct {
	ID         string            `json:"id"`
	OrderID    string            `json:"order_id"`
	IssuanceID string            `json:"issuance_id"`
	CertDigest string            `json:"cert_digest"`
	KeyDigest  string            `json:"key_digest"`
	Material   *CertMaterial     `json:"material"`
	Status     CertVersionStatus `json:"status"`
	CreatedAt  time.Time         `json:"created_at"`
}

// PlanStatus 描述部署计划的生命周期。
//
//	staging --(预检通过数达到门槛)--> activating --(全部节点激活)--> completed
//	staging / activating --(失败数超阈值或手动)--> paused --(恢复)--> 回到暂停前阶段
//	activating / paused --(已激活节点全部回退)--> rolled_back
//
// completed 与 rolled_back 为终态。
type PlanStatus string

const (
	PlanStatusStaging    PlanStatus = "staging"
	PlanStatusActivating PlanStatus = "activating"
	PlanStatusPaused     PlanStatus = "paused"
	PlanStatusCompleted  PlanStatus = "completed"
	PlanStatusRolledBack PlanStatus = "rolled_back"
)

// PlanDirection 是计划推进方向的闩锁：一旦任一节点开始回退，
// 方向永久切为 rollback，后续激活/预检回执一律拒绝，
// 保证回退与继续激活并发时只有一个方向生效。
type PlanDirection string

const (
	DirectionForward  PlanDirection = "forward"
	DirectionRollback PlanDirection = "rollback"
)

// NodeStatus 描述计划内单个节点的状态。
type NodeStatus string

const (
	NodeStatusPending    NodeStatus = "pending"     // 未领取
	NodeStatusClaimed    NodeStatus = "claimed"     // 已领取证书
	NodeStatusPrechecked NodeStatus = "prechecked"  // 预检通过
	NodeStatusActivated  NodeStatus = "activated"   // 已激活新证书
	NodeStatusFailed     NodeStatus = "failed"      // 预检或激活失败（可重新领取恢复）
	NodeStatusRolledBack NodeStatus = "rolled_back" // 已回退到原证书版本（终态）
)

// PlanNode 是计划内单个节点的执行状态。
// ExecVersion 在每次领取时递增，回执必须携带最新版本号，过期回执被拒绝。
type PlanNode struct {
	NodeID        string     `json:"node_id"`
	Status        NodeStatus `json:"status"`
	ExecVersion   int        `json:"exec_version"`
	FailureReason string     `json:"failure_reason,omitempty"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// Plan 是分阶段部署计划。目标节点集合与门槛在创建时冻结，之后不可修改。
type Plan struct {
	ID                string               `json:"id"`
	OrderID           string               `json:"order_id"`
	CertVersionID     string               `json:"cert_version_id"`
	PrevVersionID     string               `json:"prev_version_id,omitempty"`
	Nodes             []string             `json:"nodes"`
	PrecheckThreshold int                  `json:"precheck_threshold"`
	FailureThreshold  int                  `json:"failure_threshold"`
	Status            PlanStatus           `json:"status"`
	PausedFrom        PlanStatus           `json:"paused_from,omitempty"`
	Direction         PlanDirection        `json:"direction"`
	NodeStates        map[string]*PlanNode `json:"node_states"`
	CreatedAt         time.Time            `json:"created_at"`
	UpdatedAt         time.Time            `json:"updated_at"`
}

// ReceiptPhase 区分回执所处的阶段，预检与激活回执共享同一幂等命名空间。
type ReceiptPhase string

const (
	ReceiptPhasePrecheck   ReceiptPhase = "precheck"
	ReceiptPhaseActivation ReceiptPhase = "activation"
)

// ReceiptRecord 记录已处理回执的幂等信息：
// 同一回执号 + 相同内容复用原结果，相同回执号 + 不同内容报冲突。
type ReceiptRecord struct {
	ReceiptID   string       `json:"receipt_id"`
	Phase       ReceiptPhase `json:"phase"`
	ContentHash string       `json:"content_hash"`
	NodeStatus  NodeStatus   `json:"node_status"`
	PlanStatus  PlanStatus   `json:"plan_status"`
	ProcessedAt time.Time    `json:"processed_at"`
}

// Notification 是计划完成的通知事件。每个计划最多写出一条，
// 与计划进入 completed 在同一临界区内完成，保证不重不漏。
type Notification struct {
	ID               string    `json:"id"`
	PlanID           string    `json:"plan_id"`
	CertVersionID    string    `json:"cert_version_id"`
	RetiredVersionID string    `json:"retired_version_id,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

// certVersionID 由订单派生证书版本 ID，保证重复确认不会重建版本。
func certVersionID(orderID string) string { return "cv-" + orderID }

// hashParts 计算任意内容组合的 SHA-256 摘要。
func hashParts(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		io.WriteString(h, p)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CreatePlanInput 创建部署计划的入参。
type CreatePlanInput struct {
	// PlanID 由调用方提供以支持幂等创建；为空时由服务生成。
	PlanID string
	// OrderID 已签发订单，计划部署该订单的证书版本。
	OrderID string
	// Nodes 目标节点集合，创建后冻结。空集合或重复节点会被拒绝。
	Nodes []string
	// PrecheckThreshold 进入激活阶段所需的最少预检通过节点数，须在 [1, len(Nodes)] 内。
	PrecheckThreshold int
	// FailureThreshold 失败节点数超过该值时计划自动暂停，必须非负。
	FailureThreshold int
}

// CreatePlan 为已签发订单创建部署计划：冻结节点集合与门槛，计划从 staging 开始。
// 相同 PlanID + 相同内容幂等复用，相同 PlanID + 不同内容报 KindConflict。
func (s *Service) CreatePlan(in CreatePlanInput) (*PlanView, error) {
	nodes, err := normalizeNodes(in.Nodes)
	if err != nil {
		return nil, err
	}
	if in.PrecheckThreshold < 1 || in.PrecheckThreshold > len(nodes) {
		return nil, newError(KindValidation, "precheck threshold must be in [1, %d]", len(nodes))
	}
	if in.FailureThreshold < 0 {
		return nil, newError(KindValidation, "failure threshold must be non-negative")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	order := s.data.Orders[in.OrderID]
	if order == nil {
		return nil, newError(KindNotFound, "order %q not found", in.OrderID)
	}
	if order.Status != OrderStatusIssued {
		return nil, newError(KindState, "order %q is %s, cannot create plan", order.ID, order.Status)
	}
	cv := s.data.CertVersions[certVersionID(order.ID)]
	if cv == nil {
		return nil, newError(KindState, "order %q has no certificate version", order.ID)
	}

	if in.PlanID != "" {
		if existing := s.data.Plans[in.PlanID]; existing != nil {
			if existing.OrderID == in.OrderID &&
				slices.Equal(existing.Nodes, nodes) &&
				existing.PrecheckThreshold == in.PrecheckThreshold &&
				existing.FailureThreshold == in.FailureThreshold {
				v := s.planViewLocked(existing)
				return &v, nil
			}
			return nil, newError(KindConflict, "plan %q already exists with different content", in.PlanID)
		}
	}

	id := in.PlanID
	if id == "" {
		if id, err = randomID("plan"); err != nil {
			return nil, err
		}
	}

	now := s.now()
	plan := &Plan{
		ID:                id,
		OrderID:           order.ID,
		CertVersionID:     cv.ID,
		PrevVersionID:     s.currentVersionIDLocked(),
		Nodes:             nodes,
		PrecheckThreshold: in.PrecheckThreshold,
		FailureThreshold:  in.FailureThreshold,
		Status:            PlanStatusStaging,
		Direction:         DirectionForward,
		NodeStates:        make(map[string]*PlanNode, len(nodes)),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	for _, n := range nodes {
		plan.NodeStates[n] = &PlanNode{NodeID: n, Status: NodeStatusPending, UpdatedAt: now}
	}
	s.data.Plans[id] = plan
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	v := s.planViewLocked(plan)
	return &v, nil
}

// ClaimResult 节点领取证书的结果，携带秘密材料与当前执行版本。
// 这是唯一返回秘密材料的入口，普通查询不暴露。
type ClaimResult struct {
	PlanID      string
	NodeID      string
	ExecVersion int
	CertDigest  string
	Material    CertMaterial
}

// ClaimNode 节点领取证书：返回秘密材料与递增后的执行版本。
// 节点应本地校验私钥与证书匹配后再回报预检结果。
// pending / claimed / failed 状态的节点可领取（failed 重新领取即恢复）；
// 重复领取会使执行版本递增，此前版本签发的回执全部失效。
func (s *Service) ClaimNode(planID, nodeID string) (*ClaimResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	plan, node, err := s.planNodeLocked(planID, nodeID)
	if err != nil {
		return nil, err
	}
	if err := plan.forwardLocked(); err != nil {
		return nil, err
	}
	switch node.Status {
	case NodeStatusPending, NodeStatusClaimed, NodeStatusFailed:
	default:
		return nil, newError(KindState, "node %q is %s, cannot claim", nodeID, node.Status)
	}

	now := s.now()
	node.ExecVersion++
	node.Status = NodeStatusClaimed
	node.FailureReason = ""
	node.UpdatedAt = now
	plan.UpdatedAt = now
	if err := s.persistLocked(); err != nil {
		return nil, err
	}

	cv := s.data.CertVersions[plan.CertVersionID]
	return &ClaimResult{
		PlanID:      plan.ID,
		NodeID:      nodeID,
		ExecVersion: node.ExecVersion,
		CertDigest:  cv.CertDigest,
		Material:    *cv.Material,
	}, nil
}

// ReceiptInput 节点回执入参。ReceiptID 是幂等号：
// 同号同内容复用原结果，同号异内容报 KindConflict。
// CertDigest 与 ExecVersion 必须同时匹配计划的证书摘要与节点当前执行版本，
// 因此旧计划或旧领取轮次的回执无法生效。
type ReceiptInput struct {
	PlanID      string
	NodeID      string
	ReceiptID   string
	CertDigest  string
	ExecVersion int
	Outcome     Outcome
	Detail      string
}

// ReceiptResult 回执处理结果。
type ReceiptResult struct {
	// Reused 为 true 表示该回执号已处理过，本次复用原结果。
	Reused     bool
	NodeStatus NodeStatus
	PlanStatus PlanStatus
}

// ReportPrecheck 处理预检回执。节点须处于 claimed；
// 预检通过数达到冻结的门槛时，计划在同一临界区内原子进入 activating。
func (s *Service) ReportPrecheck(in ReceiptInput) (*ReceiptResult, error) {
	return s.applyReceipt(ReceiptPhasePrecheck, in)
}

// ReportActivation 处理激活回执。计划须处于 activating 且节点已预检通过；
// 全部节点激活后计划原子完成：写出唯一通知事件，新证书版本转为 current，
// 原证书版本标记为 pending_retirement 而非删除。
func (s *Service) ReportActivation(in ReceiptInput) (*ReceiptResult, error) {
	return s.applyReceipt(ReceiptPhaseActivation, in)
}

// applyReceipt 是预检/激活回执的公共路径。允许重复、乱序、迟到：
//   - 幂等检查优先于一切状态判断，重复回执返回稳定结果；
//   - 证书摘要不匹配报 KindAuth，执行版本过期报 KindState；
//   - 计划暂停、完成、已回退或方向已切为 rollback 时，新回执不改变任何状态；
//   - 失败节点数超过冻结的阈值时，计划在同一临界区内暂停。
func (s *Service) applyReceipt(phase ReceiptPhase, in ReceiptInput) (*ReceiptResult, error) {
	if in.PlanID == "" || in.NodeID == "" || in.ReceiptID == "" {
		return nil, newError(KindValidation, "plan id, node id and receipt id are required")
	}
	switch in.Outcome {
	case OutcomeSuccess, OutcomeFailure:
	default:
		return nil, newError(KindValidation, "unknown outcome %q", in.Outcome)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	plan := s.data.Plans[in.PlanID]
	if plan == nil {
		return nil, newError(KindNotFound, "plan %q not found", in.PlanID)
	}

	contentHash := hashParts(string(phase), in.PlanID, in.NodeID, in.CertDigest,
		strconv.Itoa(in.ExecVersion), string(in.Outcome), in.Detail)
	if recs := s.data.Receipts[plan.ID]; recs != nil {
		if rec, ok := recs[in.ReceiptID]; ok {
			if rec.ContentHash != contentHash {
				return nil, newError(KindConflict, "receipt %q already processed with different content", in.ReceiptID)
			}
			return &ReceiptResult{Reused: true, NodeStatus: rec.NodeStatus, PlanStatus: rec.PlanStatus}, nil
		}
	}

	node := plan.NodeStates[in.NodeID]
	if node == nil {
		return nil, newError(KindNotFound, "node %q is not part of plan %q", in.NodeID, plan.ID)
	}
	cv := s.data.CertVersions[plan.CertVersionID]
	if cv == nil || in.CertDigest != cv.CertDigest {
		return nil, newError(KindAuth, "cert digest does not match plan %q certificate version", plan.ID)
	}
	if in.ExecVersion != node.ExecVersion {
		return nil, newError(KindState, "stale execution version %d for node %q (current %d)",
			in.ExecVersion, in.NodeID, node.ExecVersion)
	}
	if err := plan.forwardLocked(); err != nil {
		return nil, err
	}

	now := s.now()
	switch phase {
	case ReceiptPhasePrecheck:
		if node.Status != NodeStatusClaimed {
			return nil, newError(KindState, "node %q is %s, cannot report precheck", node.NodeID, node.Status)
		}
	case ReceiptPhaseActivation:
		if plan.Status != PlanStatusActivating {
			return nil, newError(KindState, "plan %q is %s, not activating", plan.ID, plan.Status)
		}
		if node.Status != NodeStatusPrechecked {
			return nil, newError(KindState, "node %q is %s, cannot report activation", node.NodeID, node.Status)
		}
	}

	switch in.Outcome {
	case OutcomeSuccess:
		if phase == ReceiptPhasePrecheck {
			node.Status = NodeStatusPrechecked
		} else {
			node.Status = NodeStatusActivated
		}
	case OutcomeFailure:
		node.Status = NodeStatusFailed
		node.FailureReason = in.Detail
	}
	node.UpdatedAt = now
	plan.UpdatedAt = now

	// 失败数超阈值 -> 暂停优先于一切推进。
	if countNodes(plan, NodeStatusFailed) > plan.FailureThreshold {
		plan.PausedFrom = plan.Status
		plan.Status = PlanStatusPaused
	} else {
		// 达到预检门槛 -> 原子进入激活阶段。
		if plan.Status == PlanStatusStaging && countNodes(plan, NodeStatusPrechecked) >= plan.PrecheckThreshold {
			plan.Status = PlanStatusActivating
		}
		// 全部节点激活 -> 原子完成：唯一通知事件 + 证书版本迁移。
		if plan.Status == PlanStatusActivating && countNodes(plan, NodeStatusActivated) == len(plan.Nodes) {
			s.completePlanLocked(plan, now)
		}
	}

	if s.data.Receipts[plan.ID] == nil {
		s.data.Receipts[plan.ID] = make(map[string]*ReceiptRecord)
	}
	s.data.Receipts[plan.ID][in.ReceiptID] = &ReceiptRecord{
		ReceiptID:   in.ReceiptID,
		Phase:       phase,
		ContentHash: contentHash,
		NodeStatus:  node.Status,
		PlanStatus:  plan.Status,
		ProcessedAt: now,
	}
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return &ReceiptResult{NodeStatus: node.Status, PlanStatus: plan.Status}, nil
}

// PausePlan 手动暂停计划。staging / activating 可暂停；重复暂停幂等。
func (s *Service) PausePlan(planID string) (*PlanView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	plan := s.data.Plans[planID]
	if plan == nil {
		return nil, newError(KindNotFound, "plan %q not found", planID)
	}
	switch plan.Status {
	case PlanStatusStaging, PlanStatusActivating:
		plan.PausedFrom = plan.Status
		plan.Status = PlanStatusPaused
		plan.UpdatedAt = s.now()
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
	case PlanStatusPaused:
		// 幂等
	default:
		return nil, newError(KindState, "plan %q is %s, cannot pause", planID, plan.Status)
	}
	v := s.planViewLocked(plan)
	return &v, nil
}

// ResumePlan 恢复已暂停的计划，回到暂停前所处的阶段。
// 对运行中的计划是幂等空操作；终态计划报 KindState。
func (s *Service) ResumePlan(planID string) (*PlanView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	plan := s.data.Plans[planID]
	if plan == nil {
		return nil, newError(KindNotFound, "plan %q not found", planID)
	}
	switch plan.Status {
	case PlanStatusPaused:
		plan.Status = plan.PausedFrom
		plan.PausedFrom = ""
		plan.UpdatedAt = s.now()
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
	case PlanStatusStaging, PlanStatusActivating:
		// 幂等空操作
	default:
		return nil, newError(KindState, "plan %q is %s, cannot resume", planID, plan.Status)
	}
	v := s.planViewLocked(plan)
	return &v, nil
}

// RollbackNode 把已激活节点回退到原证书版本。首个回退生效时，
// 计划方向永久闩为 rollback：之后的预检/激活回执一律拒绝，
// 回退与继续激活并发时只有一个方向生效。重复回退同一节点幂等。
func (s *Service) RollbackNode(planID, nodeID string) (*PlanView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	plan, node, err := s.planNodeLocked(planID, nodeID)
	if err != nil {
		return nil, err
	}
	if node.Status == NodeStatusRolledBack {
		v := s.planViewLocked(plan)
		return &v, nil
	}
	switch plan.Status {
	case PlanStatusCompleted, PlanStatusRolledBack:
		return nil, newError(KindState, "plan %q is %s, cannot roll back", planID, plan.Status)
	}
	if node.Status != NodeStatusActivated {
		return nil, newError(KindState, "node %q is %s, only activated nodes can roll back", nodeID, node.Status)
	}

	now := s.now()
	plan.Direction = DirectionRollback
	node.Status = NodeStatusRolledBack
	node.UpdatedAt = now
	plan.UpdatedAt = now
	// 已激活节点全部回退 -> 计划进入终态 rolled_back。
	if countNodes(plan, NodeStatusActivated) == 0 {
		plan.Status = PlanStatusRolledBack
	}
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	v := s.planViewLocked(plan)
	return &v, nil
}

// GetPlan 查询计划及节点状态（不含秘密材料与私钥摘要）。
func (s *Service) GetPlan(planID string) (*PlanView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	plan := s.data.Plans[planID]
	if plan == nil {
		return nil, newError(KindNotFound, "plan %q not found", planID)
	}
	v := s.planViewLocked(plan)
	return &v, nil
}

// ListCertVersions 返回全部证书版本的视图（不含秘密材料与私钥摘要），
// 按创建时间、ID 排序，结果确定。
func (s *Service) ListCertVersions() []CertVersionView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]CertVersionView, 0, len(s.data.CertVersions))
	for _, cv := range s.data.CertVersions {
		out = append(out, certVersionView(cv))
	}
	slices.SortFunc(out, func(a, b CertVersionView) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// ListNotifications 返回全部计划完成通知事件的副本。
func (s *Service) ListNotifications() []Notification {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Notification, len(s.data.Notifications))
	copy(out, s.data.Notifications)
	return out
}

// completePlanLocked 原子完成计划：写唯一通知事件，新证书版本转为 current，
// 原证书版本标记为 pending_retirement（不删除）。调用方须持有锁。
func (s *Service) completePlanLocked(plan *Plan, now time.Time) {
	plan.Status = PlanStatusCompleted
	cv := s.data.CertVersions[plan.CertVersionID]
	if cv != nil && cv.Status == CertVersionStaged {
		cv.Status = CertVersionCurrent
	}
	if plan.PrevVersionID != "" {
		if prev := s.data.CertVersions[plan.PrevVersionID]; prev != nil && prev.Status == CertVersionCurrent {
			prev.Status = CertVersionPendingRetirement
		}
	}
	s.data.Notifications = append(s.data.Notifications, Notification{
		ID:               "notify-" + plan.ID,
		PlanID:           plan.ID,
		CertVersionID:    plan.CertVersionID,
		RetiredVersionID: plan.PrevVersionID,
		CreatedAt:        now,
	})
}

// forwardLocked 校验计划仍允许向前推进（领取、预检、激活的公共门禁）。
func (p *Plan) forwardLocked() error {
	switch p.Status {
	case PlanStatusPaused:
		return newError(KindState, "plan %q is paused", p.ID)
	case PlanStatusCompleted, PlanStatusRolledBack:
		return newError(KindState, "plan %q is finalized (%s)", p.ID, p.Status)
	}
	if p.Direction == DirectionRollback {
		return newError(KindState, "plan %q is rolling back, forward progress rejected", p.ID)
	}
	return nil
}

func (s *Service) planNodeLocked(planID, nodeID string) (*Plan, *PlanNode, error) {
	plan := s.data.Plans[planID]
	if plan == nil {
		return nil, nil, newError(KindNotFound, "plan %q not found", planID)
	}
	node := plan.NodeStates[nodeID]
	if node == nil {
		return nil, nil, newError(KindNotFound, "node %q is not part of plan %q", nodeID, planID)
	}
	return plan, node, nil
}

// currentVersionIDLocked 返回当前生效的证书版本 ID，没有则返回空串。
func (s *Service) currentVersionIDLocked() string {
	for _, cv := range s.data.CertVersions {
		if cv.Status == CertVersionCurrent {
			return cv.ID
		}
	}
	return ""
}

func countNodes(plan *Plan, status NodeStatus) int {
	n := 0
	for _, node := range plan.NodeStates {
		if node.Status == status {
			n++
		}
	}
	return n
}

func normalizeNodes(nodes []string) ([]string, error) {
	if len(nodes) == 0 {
		return nil, newError(KindValidation, "at least one node is required")
	}
	out := make([]string, 0, len(nodes))
	seen := make(map[string]struct{}, len(nodes))
	for _, n := range nodes {
		if n == "" || strings.TrimSpace(n) != n {
			return nil, newError(KindValidation, "invalid node id %q", n)
		}
		if _, dup := seen[n]; dup {
			return nil, newError(KindValidation, "duplicate node %q", n)
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	slices.Sort(out)
	return out, nil
}

// PlanNodeView 是节点的对外视图。
type PlanNodeView struct {
	NodeID        string
	Status        NodeStatus
	ExecVersion   int
	FailureReason string
	UpdatedAt     time.Time
}

// PlanView 是计划的对外视图，不暴露秘密材料与私钥摘要。
type PlanView struct {
	ID                string
	OrderID           string
	CertVersionID     string
	PrevVersionID     string
	CertDigest        string
	Status            PlanStatus
	Direction         PlanDirection
	PrecheckThreshold int
	FailureThreshold  int
	PrecheckedCount   int
	ActivatedCount    int
	FailedCount       int
	Nodes             []PlanNodeView
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

func (s *Service) planViewLocked(p *Plan) PlanView {
	v := PlanView{
		ID:                p.ID,
		OrderID:           p.OrderID,
		CertVersionID:     p.CertVersionID,
		PrevVersionID:     p.PrevVersionID,
		Status:            p.Status,
		Direction:         p.Direction,
		PrecheckThreshold: p.PrecheckThreshold,
		FailureThreshold:  p.FailureThreshold,
		PrecheckedCount:   countNodes(p, NodeStatusPrechecked),
		ActivatedCount:    countNodes(p, NodeStatusActivated),
		FailedCount:       countNodes(p, NodeStatusFailed),
		Nodes:             make([]PlanNodeView, 0, len(p.Nodes)),
		CreatedAt:         p.CreatedAt,
		UpdatedAt:         p.UpdatedAt,
	}
	if cv := s.data.CertVersions[p.CertVersionID]; cv != nil {
		v.CertDigest = cv.CertDigest
	}
	for _, id := range p.Nodes {
		n := p.NodeStates[id]
		v.Nodes = append(v.Nodes, PlanNodeView{
			NodeID:        n.NodeID,
			Status:        n.Status,
			ExecVersion:   n.ExecVersion,
			FailureReason: n.FailureReason,
			UpdatedAt:     n.UpdatedAt,
		})
	}
	return v
}

// CertVersionView 是证书版本的对外视图，不暴露秘密材料与私钥摘要。
type CertVersionView struct {
	ID         string
	OrderID    string
	IssuanceID string
	CertDigest string
	Status     CertVersionStatus
	CreatedAt  time.Time
}

func certVersionView(cv *CertVersion) CertVersionView {
	return CertVersionView{
		ID:         cv.ID,
		OrderID:    cv.OrderID,
		IssuanceID: cv.IssuanceID,
		CertDigest: cv.CertDigest,
		Status:     cv.Status,
		CreatedAt:  cv.CreatedAt,
	}
}
