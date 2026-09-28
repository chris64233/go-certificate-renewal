package certificaterenewal

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// mustIssue 驱动订单走完全部挑战并确认签发，返回创建结果（含挑战秘密）。
func mustIssue(t *testing.T, svc *Service, orderID string, material CertMaterial) *CreateOrderResult {
	t.Helper()
	domain := orderID + ".example.com"
	res := mustCreate(t, svc, orderID, []string{domain}, time.Hour)
	mustCallback(t, svc, orderID, domain, "cb-"+orderID, res.Secrets[domain], OutcomeSuccess)
	if _, err := svc.ConfirmIssuance(orderID, "iss-"+orderID, material); err != nil {
		t.Fatalf("ConfirmIssuance(%s): %v", orderID, err)
	}
	return res
}

func mustCreatePlan(t *testing.T, svc *Service, planID, orderID string, nodes []string, precheck, failure int) *PlanView {
	t.Helper()
	v, err := svc.CreatePlan(CreatePlanInput{
		PlanID: planID, OrderID: orderID, Nodes: nodes,
		PrecheckThreshold: precheck, FailureThreshold: failure,
	})
	if err != nil {
		t.Fatalf("CreatePlan(%s): %v", planID, err)
	}
	return v
}

func mustClaim(t *testing.T, svc *Service, planID, nodeID string) *ClaimResult {
	t.Helper()
	c, err := svc.ClaimNode(planID, nodeID)
	if err != nil {
		t.Fatalf("ClaimNode(%s/%s): %v", planID, nodeID, err)
	}
	return c
}

func receipt(planID, nodeID, receiptID string, claim *ClaimResult, outcome Outcome) ReceiptInput {
	return ReceiptInput{
		PlanID: planID, NodeID: nodeID, ReceiptID: receiptID,
		CertDigest: claim.CertDigest, ExecVersion: claim.ExecVersion, Outcome: outcome,
	}
}

func mustPrecheck(t *testing.T, svc *Service, in ReceiptInput) *ReceiptResult {
	t.Helper()
	r, err := svc.ReportPrecheck(in)
	if err != nil {
		t.Fatalf("ReportPrecheck(%s/%s): %v", in.PlanID, in.NodeID, err)
	}
	return r
}

func mustActivation(t *testing.T, svc *Service, in ReceiptInput) *ReceiptResult {
	t.Helper()
	r, err := svc.ReportActivation(in)
	if err != nil {
		t.Fatalf("ReportActivation(%s/%s): %v", in.PlanID, in.NodeID, err)
	}
	return r
}

func TestConfirmIssuanceCreatesStagedCertVersion(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1", testMaterial)

	versions := svc.ListCertVersions()
	if len(versions) != 1 {
		t.Fatalf("expected one cert version, got %d", len(versions))
	}
	cv := versions[0]
	if cv.ID != "cv-o1" || cv.Status != CertVersionStaged || cv.IssuanceID != "iss-o1" {
		t.Fatalf("unexpected cert version: %+v", cv)
	}
	if cv.CertDigest != hashParts(testMaterial.CertPEM) {
		t.Fatal("cert digest must be derived from material")
	}

	// 秘密材料只持久化、不进查询视图。
	stored := svc.data.CertVersions["cv-o1"]
	if stored.Material == nil || stored.Material.CertPEM != testMaterial.CertPEM {
		t.Fatal("material must be persisted for node claim")
	}
	if stored.KeyDigest == "" || stored.KeyDigest == testMaterial.KeyPEM {
		t.Fatal("private key must be persisted as digest-derived material only")
	}
}

func TestCreatePlanFreezesNodesAndThresholds(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1", testMaterial)

	// 未签发订单不能建计划。
	mustCreate(t, svc, "o2", []string{"x.example.com"}, time.Hour)
	if _, err := svc.CreatePlan(CreatePlanInput{OrderID: "o2", Nodes: []string{"n1"}, PrecheckThreshold: 1}); err == nil {
		t.Fatal("plan on non-issued order should fail")
	} else {
		requireKind(t, err, KindState)
	}

	// 参数校验。
	if _, err := svc.CreatePlan(CreatePlanInput{OrderID: "o1", Nodes: nil, PrecheckThreshold: 1}); err == nil {
		t.Fatal("empty nodes should fail")
	} else {
		requireKind(t, err, KindValidation)
	}
	if _, err := svc.CreatePlan(CreatePlanInput{OrderID: "o1", Nodes: []string{"n1", "n1"}, PrecheckThreshold: 1}); err == nil {
		t.Fatal("duplicate nodes should fail")
	} else {
		requireKind(t, err, KindValidation)
	}
	if _, err := svc.CreatePlan(CreatePlanInput{OrderID: "o1", Nodes: []string{"n1"}, PrecheckThreshold: 2}); err == nil {
		t.Fatal("precheck threshold above node count should fail")
	} else {
		requireKind(t, err, KindValidation)
	}
	if _, err := svc.CreatePlan(CreatePlanInput{OrderID: "o1", Nodes: []string{"n1"}, PrecheckThreshold: 1, FailureThreshold: -1}); err == nil {
		t.Fatal("negative failure threshold should fail")
	} else {
		requireKind(t, err, KindValidation)
	}

	plan := mustCreatePlan(t, svc, "p1", "o1", []string{"n2", "n1", "n3"}, 2, 1)
	if plan.Status != PlanStatusStaging || plan.Direction != DirectionForward {
		t.Fatalf("new plan should be staging/forward, got %+v", plan)
	}
	wantNodes := []string{"n1", "n2", "n3"}
	if fmt.Sprint(nodeIDs(plan)) != fmt.Sprint(wantNodes) {
		t.Fatalf("nodes not frozen/sorted: %v", nodeIDs(plan))
	}
	if plan.CertVersionID != "cv-o1" {
		t.Fatalf("plan must bind issued cert version, got %s", plan.CertVersionID)
	}

	// 幂等创建：同号同内容复用，同号异内容冲突。
	again, err := svc.CreatePlan(CreatePlanInput{PlanID: "p1", OrderID: "o1", Nodes: wantNodes, PrecheckThreshold: 2, FailureThreshold: 1})
	if err != nil || again.Status != plan.Status {
		t.Fatalf("idempotent create: %v %+v", err, again)
	}
	_, err = svc.CreatePlan(CreatePlanInput{PlanID: "p1", OrderID: "o1", Nodes: wantNodes, PrecheckThreshold: 3, FailureThreshold: 1})
	requireKind(t, err, KindConflict)
}

func nodeIDs(p *PlanView) []string {
	out := make([]string, 0, len(p.Nodes))
	for _, n := range p.Nodes {
		out = append(out, n.NodeID)
	}
	return out
}

func TestClaimReturnsMaterialOnceAndBumpsExecVersion(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1", testMaterial)
	mustCreatePlan(t, svc, "p1", "o1", []string{"n1"}, 1, 0)

	c1 := mustClaim(t, svc, "p1", "n1")
	if c1.Material != testMaterial {
		t.Fatalf("claim must return secret material, got %+v", c1.Material)
	}
	if c1.ExecVersion != 1 {
		t.Fatalf("first claim exec version = %d, want 1", c1.ExecVersion)
	}

	// 重复领取：执行版本递增，旧版本回执失效。
	c2 := mustClaim(t, svc, "p1", "n1")
	if c2.ExecVersion != 2 {
		t.Fatalf("re-claim exec version = %d, want 2", c2.ExecVersion)
	}
	_, err := svc.ReportPrecheck(receipt("p1", "n1", "r-stale", c1, OutcomeSuccess))
	requireKind(t, err, KindState)

	// 普通查询不暴露秘密材料：视图类型不含 Material，此处验证状态与版本可见。
	view, err := svc.GetPlan("p1")
	if err != nil {
		t.Fatalf("GetPlan: %v", err)
	}
	if view.Nodes[0].Status != NodeStatusClaimed || view.Nodes[0].ExecVersion != 2 {
		t.Fatalf("unexpected node view: %+v", view.Nodes[0])
	}
}

func TestPrecheckThresholdTriggersActivatingAtomically(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1", testMaterial)
	mustCreatePlan(t, svc, "p1", "o1", []string{"n1", "n2", "n3"}, 2, 5)

	c1 := mustClaim(t, svc, "p1", "n1")
	r := mustPrecheck(t, svc, receipt("p1", "n1", "r1", c1, OutcomeSuccess))
	if r.PlanStatus != PlanStatusStaging {
		t.Fatalf("below threshold should stay staging, got %s", r.PlanStatus)
	}

	// 激活回执在门槛达到前不被接受。
	_, err := svc.ReportActivation(receipt("p1", "n1", "r-act-early", c1, OutcomeSuccess))
	requireKind(t, err, KindState)

	c2 := mustClaim(t, svc, "p1", "n2")
	r = mustPrecheck(t, svc, receipt("p1", "n2", "r2", c2, OutcomeSuccess))
	if r.PlanStatus != PlanStatusActivating {
		t.Fatalf("reaching threshold must atomically enter activating, got %s", r.PlanStatus)
	}
}

func TestReceiptReplayAndConflict(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1", testMaterial)
	mustCreatePlan(t, svc, "p1", "o1", []string{"n1"}, 1, 0)
	c := mustClaim(t, svc, "p1", "n1")

	first := mustPrecheck(t, svc, receipt("p1", "n1", "r1", c, OutcomeSuccess))
	replay := mustPrecheck(t, svc, receipt("p1", "n1", "r1", c, OutcomeSuccess))
	if first.Reused || !replay.Reused {
		t.Fatalf("replay must reuse stored result: first=%+v replay=%+v", first, replay)
	}
	if replay.NodeStatus != first.NodeStatus || replay.PlanStatus != first.PlanStatus {
		t.Fatal("replayed result must equal original result")
	}

	// 同号异内容 -> 冲突（即使计划已推进，幂等检查仍优先）。
	in := receipt("p1", "n1", "r1", c, OutcomeFailure)
	_, err := svc.ReportPrecheck(in)
	requireKind(t, err, KindConflict)
}

func TestReceiptMustMatchCertDigest(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1", testMaterial)
	mustCreatePlan(t, svc, "p1", "o1", []string{"n1"}, 1, 0)
	c := mustClaim(t, svc, "p1", "n1")

	in := receipt("p1", "n1", "r1", c, OutcomeSuccess)
	in.CertDigest = hashParts("forged-cert")
	_, err := svc.ReportPrecheck(in)
	requireKind(t, err, KindAuth)

	view, _ := svc.GetPlan("p1")
	if view.Nodes[0].Status != NodeStatusClaimed {
		t.Fatal("digest mismatch must not mutate node")
	}
}

func TestActivationCompletesPlanWithUniqueNotification(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1", testMaterial)
	mustCreatePlan(t, svc, "p1", "o1", []string{"n1", "n2"}, 2, 5)

	for i, n := range []string{"n1", "n2"} {
		c := mustClaim(t, svc, "p1", n)
		mustPrecheck(t, svc, receipt("p1", n, fmt.Sprintf("pre-%d", i), c, OutcomeSuccess))
	}
	c1 := mustClaimView(t, svc, "p1", "n1")
	r := mustActivation(t, svc, receipt("p1", "n1", "act-1", c1, OutcomeSuccess))
	if r.PlanStatus != PlanStatusActivating {
		t.Fatalf("one node remaining, plan should stay activating, got %s", r.PlanStatus)
	}

	c2 := mustClaimView(t, svc, "p1", "n2")
	r = mustActivation(t, svc, receipt("p1", "n2", "act-2", c2, OutcomeSuccess))
	if r.PlanStatus != PlanStatusCompleted {
		t.Fatalf("all nodes activated must complete plan, got %s", r.PlanStatus)
	}

	// 唯一通知事件。
	notifications := svc.ListNotifications()
	if len(notifications) != 1 {
		t.Fatalf("expected exactly one notification, got %d", len(notifications))
	}
	if notifications[0].ID != "notify-p1" || notifications[0].CertVersionID != "cv-o1" {
		t.Fatalf("unexpected notification: %+v", notifications[0])
	}

	// 新证书版本转为 current。
	versions := svc.ListCertVersions()
	if len(versions) != 1 || versions[0].Status != CertVersionCurrent {
		t.Fatalf("cert version should be current after completion: %+v", versions)
	}

	// 完成后新回执与回退均被拒绝（重复回执仍幂等返回）。
	replay := mustActivation(t, svc, receipt("p1", "n2", "act-2", c2, OutcomeSuccess))
	if !replay.Reused || replay.PlanStatus != PlanStatusCompleted {
		t.Fatalf("replay after completion must return stored result, got %+v", replay)
	}
	_, err := svc.ReportActivation(receipt("p1", "n1", "act-late", c1, OutcomeSuccess))
	requireKind(t, err, KindState)
	if _, err := svc.RollbackNode("p1", "n1"); err == nil {
		t.Fatal("completed plan must not roll back")
	} else {
		requireKind(t, err, KindState)
	}
}

// mustClaimView 读取节点当前执行版本，构造匹配的回执（不重新领取）。
func mustClaimView(t *testing.T, svc *Service, planID, nodeID string) *ClaimResult {
	t.Helper()
	view, err := svc.GetPlan(planID)
	if err != nil {
		t.Fatalf("GetPlan: %v", err)
	}
	for _, n := range view.Nodes {
		if n.NodeID == nodeID {
			return &ClaimResult{PlanID: planID, NodeID: nodeID, ExecVersion: n.ExecVersion, CertDigest: view.CertDigest}
		}
	}
	t.Fatalf("node %s not found", nodeID)
	return nil
}

func TestOldVersionMarkedPendingRetirementNotDeleted(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1", testMaterial)
	mustCreatePlan(t, svc, "p1", "o1", []string{"n1"}, 1, 5)
	c := mustClaim(t, svc, "p1", "n1")
	mustPrecheck(t, svc, receipt("p1", "n1", "pre-1", c, OutcomeSuccess))
	mustActivation(t, svc, receipt("p1", "n1", "act-1", c, OutcomeSuccess))

	// 第二轮续期：新订单、新证书版本、新计划。
	material2 := CertMaterial{CertPEM: "cert-pem-2", KeyPEM: "key-pem-2"}
	mustIssue(t, svc, "o2", material2)
	plan2 := mustCreatePlan(t, svc, "p2", "o2", []string{"n1"}, 1, 5)
	if plan2.PrevVersionID != "cv-o1" {
		t.Fatalf("plan must record previous version, got %q", plan2.PrevVersionID)
	}
	c2 := mustClaim(t, svc, "p2", "n1")
	mustPrecheck(t, svc, receipt("p2", "n1", "pre-1", c2, OutcomeSuccess))
	mustActivation(t, svc, receipt("p2", "n1", "act-1", c2, OutcomeSuccess))

	versions := map[string]CertVersionView{}
	for _, v := range svc.ListCertVersions() {
		versions[v.ID] = v
	}
	if versions["cv-o2"].Status != CertVersionCurrent {
		t.Fatalf("new version should be current, got %s", versions["cv-o2"].Status)
	}
	// 旧证书标记为待退役而非删除。
	old, ok := versions["cv-o1"]
	if !ok {
		t.Fatal("old cert version must not be deleted")
	}
	if old.Status != CertVersionPendingRetirement {
		t.Fatalf("old version should be pending_retirement, got %s", old.Status)
	}

	notifications := svc.ListNotifications()
	if len(notifications) != 2 || notifications[1].RetiredVersionID != "cv-o1" {
		t.Fatalf("completion notification must reference retired version: %+v", notifications)
	}
}

func TestFailureThresholdPausesPlanAndResumeRestores(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1", testMaterial)
	mustCreatePlan(t, svc, "p1", "o1", []string{"n1", "n2", "n3"}, 2, 1)

	c1 := mustClaim(t, svc, "p1", "n1")
	r := mustPrecheck(t, svc, receipt("p1", "n1", "pre-1", c1, OutcomeFailure))
	if r.PlanStatus != PlanStatusStaging {
		t.Fatalf("one failure within threshold, got %s", r.PlanStatus)
	}

	c2 := mustClaim(t, svc, "p1", "n2")
	r = mustPrecheck(t, svc, receipt("p1", "n2", "pre-2", c2, OutcomeFailure))
	if r.PlanStatus != PlanStatusPaused {
		t.Fatalf("failures over threshold must pause plan, got %s", r.PlanStatus)
	}

	// 暂停期间：领取与新回执被拒绝，重复回执仍幂等返回。
	if _, err := svc.ClaimNode("p1", "n3"); err == nil {
		t.Fatal("claim on paused plan should fail")
	} else {
		requireKind(t, err, KindState)
	}
	c3stale := &ClaimResult{PlanID: "p1", NodeID: "n3", ExecVersion: 1, CertDigest: c2.CertDigest}
	if _, err := svc.ReportPrecheck(receipt("p1", "n3", "pre-3", c3stale, OutcomeSuccess)); err == nil {
		t.Fatal("receipt on paused plan should fail")
	} else {
		requireKind(t, err, KindState)
	}
	replay := mustPrecheck(t, svc, receipt("p1", "n2", "pre-2", c2, OutcomeFailure))
	if !replay.Reused || replay.PlanStatus != PlanStatusPaused {
		t.Fatalf("replay during pause must return stored result, got %+v", replay)
	}

	// 恢复后回到暂停前阶段，失败节点可重新领取恢复。
	view, err := svc.ResumePlan("p1")
	if err != nil || view.Status != PlanStatusStaging {
		t.Fatalf("resume: %v %+v", err, view)
	}
	c1retry := mustClaim(t, svc, "p1", "n1")
	r = mustPrecheck(t, svc, receipt("p1", "n1", "pre-1-retry", c1retry, OutcomeSuccess))
	if r.NodeStatus != NodeStatusPrechecked {
		t.Fatalf("failed node should recover after re-claim, got %s", r.NodeStatus)
	}

	// 重复暂停/恢复幂等。
	if _, err := svc.PausePlan("p1"); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if _, err := svc.PausePlan("p1"); err != nil {
		t.Fatalf("repeat pause should be idempotent: %v", err)
	}
	if _, err := svc.ResumePlan("p1"); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if _, err := svc.ResumePlan("p1"); err != nil {
		t.Fatalf("repeat resume should be idempotent: %v", err)
	}
}

func TestRollbackLatchesDirection(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1", testMaterial)
	mustCreatePlan(t, svc, "p1", "o1", []string{"n1", "n2"}, 2, 5)

	claims := map[string]*ClaimResult{}
	for _, n := range []string{"n1", "n2"} {
		claims[n] = mustClaim(t, svc, "p1", n)
		mustPrecheck(t, svc, receipt("p1", n, "pre-"+n, claims[n], OutcomeSuccess))
	}
	mustActivation(t, svc, receipt("p1", "n1", "act-n1", claims["n1"], OutcomeSuccess))

	// 回退已激活节点：方向闩为 rollback。
	view, err := svc.RollbackNode("p1", "n1")
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if view.Direction != DirectionRollback || view.Nodes[0].Status != NodeStatusRolledBack {
		t.Fatalf("unexpected view after rollback: %+v", view)
	}

	// 继续激活的回执被拒绝：回退与激活并发时只有一个方向生效。
	_, err = svc.ReportActivation(receipt("p1", "n2", "act-n2", claims["n2"], OutcomeSuccess))
	requireKind(t, err, KindState)

	// 旧回执不能让已回退节点重新激活旧证书。
	_, err = svc.ReportActivation(receipt("p1", "n1", "act-n1-late", claims["n1"], OutcomeSuccess))
	requireKind(t, err, KindState)
	_, err = svc.ReportActivation(receipt("p1", "n1", "act-n1", claims["n1"], OutcomeSuccess))
	if err != nil {
		t.Fatalf("original receipt replay must stay idempotent, got %v", err)
	}

	// 重复回退幂等；已激活节点全部回退后计划进入终态。
	if _, err := svc.RollbackNode("p1", "n1"); err != nil {
		t.Fatalf("repeat rollback should be idempotent: %v", err)
	}
	view, _ = svc.GetPlan("p1")
	if view.Status != PlanStatusRolledBack {
		t.Fatalf("all activated nodes rolled back, plan should be rolled_back, got %s", view.Status)
	}
	if len(svc.ListNotifications()) != 0 {
		t.Fatal("rolled-back plan must not emit completion notification")
	}
	// 新证书版本仍保持 staged，未替换当前证书。
	if v := svc.ListCertVersions()[0]; v.Status != CertVersionStaged {
		t.Fatalf("rolled-back plan must not promote cert version, got %s", v.Status)
	}
}

func TestOutOfOrderReceipts(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1", testMaterial)
	mustCreatePlan(t, svc, "p1", "o1", []string{"n1", "n2"}, 1, 5)

	// 激活回执先于预检到达：被拒绝但不污染状态。
	c1 := mustClaim(t, svc, "p1", "n1")
	_, err := svc.ReportActivation(receipt("p1", "n1", "act-early", c1, OutcomeSuccess))
	requireKind(t, err, KindState)

	mustPrecheck(t, svc, receipt("p1", "n1", "pre-1", c1, OutcomeSuccess))
	r := mustActivation(t, svc, receipt("p1", "n1", "act-1", c1, OutcomeSuccess))
	if r.NodeStatus != NodeStatusActivated {
		t.Fatalf("activation after precheck should apply, got %s", r.NodeStatus)
	}

	// 迟到的重复预检回执：幂等返回，不影响已激活节点。
	replay := mustPrecheck(t, svc, receipt("p1", "n1", "pre-1", c1, OutcomeSuccess))
	if !replay.Reused {
		t.Fatal("late duplicate precheck receipt must reuse stored result")
	}
	view, _ := svc.GetPlan("p1")
	if view.Nodes[0].Status != NodeStatusActivated {
		t.Fatalf("late receipt must not regress node, got %s", view.Nodes[0].Status)
	}
}

func TestConcurrentFinalActivationsEmitExactlyOneNotification(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1", testMaterial)
	mustCreatePlan(t, svc, "p1", "o1", []string{"n1"}, 1, 5)
	c := mustClaim(t, svc, "p1", "n1")
	mustPrecheck(t, svc, receipt("p1", "n1", "pre-1", c, OutcomeSuccess))

	const racers = 32
	var wg sync.WaitGroup
	errs := make([]error, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			in := receipt("p1", "n1", fmt.Sprintf("act-%d", i), c, OutcomeSuccess)
			_, errs[i] = svc.ReportActivation(in)
		}(i)
	}
	wg.Wait()

	applied := 0
	for i := range racers {
		if errs[i] == nil {
			applied++
		} else {
			requireKind(t, errs[i], KindState)
		}
	}
	if applied != 1 {
		t.Fatalf("exactly one concurrent activation may apply, got %d", applied)
	}
	if n := len(svc.ListNotifications()); n != 1 {
		t.Fatalf("exactly one notification expected, got %d", n)
	}
}

func TestConcurrentActivationVsRollbackSingleDirection(t *testing.T) {
	for i := 0; i < 20; i++ {
		svc := newTestService(t, newFakeClock())
		mustIssue(t, svc, "o1", testMaterial)
		mustCreatePlan(t, svc, "p1", "o1", []string{"n1", "n2"}, 2, 5)
		claims := map[string]*ClaimResult{}
		for _, n := range []string{"n1", "n2"} {
			claims[n] = mustClaim(t, svc, "p1", n)
			mustPrecheck(t, svc, receipt("p1", n, "pre-"+n, claims[n], OutcomeSuccess))
		}
		mustActivation(t, svc, receipt("p1", "n1", "act-n1", claims["n1"], OutcomeSuccess))

		// n2 的激活回执与 n1 的回退并发：结果必须自洽。
		var wg sync.WaitGroup
		var actErr, rbErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, actErr = svc.ReportActivation(receipt("p1", "n2", "act-n2", claims["n2"], OutcomeSuccess))
		}()
		go func() {
			defer wg.Done()
			_, rbErr = svc.RollbackNode("p1", "n1")
		}()
		wg.Wait()

		view, _ := svc.GetPlan("p1")
		n2 := view.Nodes[1]
		if rbErr != nil {
			// 激活先生效：计划完成，回退被拒绝，方向保持 forward。
			requireKind(t, rbErr, KindState)
			if actErr != nil {
				t.Fatalf("rollback rejected but activation also failed: %v", actErr)
			}
			if view.Status != PlanStatusCompleted || view.Direction != DirectionForward || n2.Status != NodeStatusActivated {
				t.Fatalf("activation-won outcome inconsistent: %+v", view)
			}
			continue
		}
		// 回退先生效：方向闩为 rollback，之后不能再有任何前进。
		if view.Direction != DirectionRollback {
			t.Fatal("rollback must latch direction")
		}
		if actErr == nil {
			// 激活在回退前的临界区内生效：n2 已激活，但之后不能再前进。
			if n2.Status != NodeStatusActivated {
				t.Fatalf("activation applied but node is %s", n2.Status)
			}
		} else {
			requireKind(t, actErr, KindState)
			if n2.Status != NodeStatusPrechecked {
				t.Fatalf("rejected activation must not mutate node, got %s", n2.Status)
			}
		}
		// 无论哪种结果，后续前进操作一律拒绝。
		c2 := mustClaimView(t, svc, "p1", "n2")
		if _, err := svc.ReportActivation(receipt("p1", "n2", "act-n2-later", c2, OutcomeSuccess)); err == nil {
			t.Fatal("forward progress after rollback latch must be rejected")
		} else {
			requireKind(t, err, KindState)
		}
	}
}

func TestDeployFilePersisterRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	clock := newFakeClock()
	key := []byte("stable-key")

	svc, err := NewService(NewFilePersister(path), WithClock(clock.Now), WithDigestKey(key))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	mustIssue(t, svc, "o1", testMaterial)
	mustCreatePlan(t, svc, "p1", "o1", []string{"n1", "n2"}, 2, 1)
	c := mustClaim(t, svc, "p1", "n1")
	mustPrecheck(t, svc, receipt("p1", "n1", "pre-1", c, OutcomeSuccess))

	// 模拟重启：计划、节点状态、证书材料全部恢复。
	svc2, err := NewService(NewFilePersister(path), WithClock(clock.Now), WithDigestKey(key))
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	view, err := svc2.GetPlan("p1")
	if err != nil {
		t.Fatalf("GetPlan after reload: %v", err)
	}
	if view.Status != PlanStatusStaging || view.Nodes[0].Status != NodeStatusPrechecked {
		t.Fatalf("plan state not persisted: %+v", view)
	}

	// 重启后回执可继续推进直至完成。
	c2 := mustClaim(t, svc2, "p1", "n2")
	mustPrecheck(t, svc2, receipt("p1", "n2", "pre-2", c2, OutcomeSuccess))
	c1v := mustClaimView(t, svc2, "p1", "n1")
	mustActivation(t, svc2, receipt("p1", "n1", "act-1", c1v, OutcomeSuccess))
	c2v := mustClaimView(t, svc2, "p1", "n2")
	r := mustActivation(t, svc2, receipt("p1", "n2", "act-2", c2v, OutcomeSuccess))
	if r.PlanStatus != PlanStatusCompleted {
		t.Fatalf("expected completed after reload, got %s", r.PlanStatus)
	}
	if n := len(svc2.ListNotifications()); n != 1 {
		t.Fatalf("expected one notification after reload, got %d", n)
	}
}
