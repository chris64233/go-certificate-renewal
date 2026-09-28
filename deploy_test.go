package certificaterenewal

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testMaterial() CertMaterial {
	return CertMaterial{
		CertPEM: "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
		KeyPEM:  "-----BEGIN KEY-----\nkey\n-----END KEY-----",
	}
}

// mustIssue 走完订单流程并确认签发，返回证书版本视图。
func mustIssue(t *testing.T, svc *Service, orderID string) CertVersionView {
	t.Helper()
	res := mustCreate(t, svc, orderID, []string{orderID + ".example.com"}, time.Hour)
	mustCallback(t, svc, orderID, orderID+".example.com", "cb-"+orderID,
		res.Secrets[orderID+".example.com"], OutcomeSuccess)
	if _, err := svc.ConfirmIssuance(orderID, "iss-"+orderID, testMaterial()); err != nil {
		t.Fatalf("ConfirmIssuance(%s): %v", orderID, err)
	}
	for _, cv := range svc.ListCertVersions() {
		if cv.OrderID == orderID {
			return cv
		}
	}
	t.Fatalf("no cert version for order %s", orderID)
	return CertVersionView{}
}

func mustPlan(t *testing.T, svc *Service, planID, orderID string, nodes []string, precheck, failure int) *PlanView {
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
	res, err := svc.ClaimNode(planID, nodeID)
	if err != nil {
		t.Fatalf("ClaimNode(%s/%s): %v", planID, nodeID, err)
	}
	return res
}

func mustPrecheck(t *testing.T, svc *Service, planID, nodeID, receiptID string, claim *ClaimResult, outcome Outcome) *ReceiptResult {
	t.Helper()
	res, err := svc.ReportPrecheck(ReceiptInput{
		PlanID: planID, NodeID: nodeID, ReceiptID: receiptID,
		CertDigest: claim.CertDigest, ExecVersion: claim.ExecVersion, Outcome: outcome,
	})
	if err != nil {
		t.Fatalf("ReportPrecheck(%s/%s): %v", planID, nodeID, err)
	}
	return res
}

func mustActivate(t *testing.T, svc *Service, planID, nodeID, receiptID string, claim *ClaimResult) *ReceiptResult {
	t.Helper()
	res, err := svc.ReportActivation(ReceiptInput{
		PlanID: planID, NodeID: nodeID, ReceiptID: receiptID,
		CertDigest: claim.CertDigest, ExecVersion: claim.ExecVersion, Outcome: OutcomeSuccess,
	})
	if err != nil {
		t.Fatalf("ReportActivation(%s/%s): %v", planID, nodeID, err)
	}
	return res
}

// currentClaim 根据计划视图构造节点当前执行版本对应的回执凭据。
func currentClaim(t *testing.T, svc *Service, planID, nodeID string) *ClaimResult {
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
	t.Fatalf("node %s not in plan %s", nodeID, planID)
	return nil
}

func nodeIDs(p *PlanView) []string {
	out := make([]string, 0, len(p.Nodes))
	for _, n := range p.Nodes {
		out = append(out, n.NodeID)
	}
	return out
}

func TestConfirmIssuanceCreatesStagedCertVersion(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	cv := mustIssue(t, svc, "o1")

	if cv.Status != CertVersionStaged {
		t.Fatalf("new cert version must be staged, got %s", cv.Status)
	}
	if cv.CertDigest == "" || cv.CertDigest == testMaterial().CertPEM {
		t.Fatalf("cert digest must be a digest, got %q", cv.CertDigest)
	}
	// 秘密材料只持久化，供领取使用；查询视图不携带。
	stored := svc.data.CertVersions[cv.ID]
	if stored.Material == nil || stored.Material.KeyPEM != testMaterial().KeyPEM {
		t.Fatal("material must be persisted for claiming")
	}
}

func TestCreatePlanFreezesNodesAndThresholds(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1")

	plan := mustPlan(t, svc, "p1", "o1", []string{"n2", "n1", "n3"}, 2, 1)
	if plan.Status != PlanStatusStaging || plan.Direction != DirectionForward {
		t.Fatalf("unexpected initial plan state: %+v", plan)
	}
	if fmt.Sprint(nodeIDs(plan)) != "[n1 n2 n3]" {
		t.Fatalf("nodes not frozen/sorted: %v", nodeIDs(plan))
	}
	if plan.PrecheckThreshold != 2 || plan.FailureThreshold != 1 {
		t.Fatalf("thresholds not frozen: %+v", plan)
	}

	// 幂等创建：同 ID 同内容复用。
	again, err := svc.CreatePlan(CreatePlanInput{
		PlanID: "p1", OrderID: "o1", Nodes: []string{"n1", "n2", "n3"},
		PrecheckThreshold: 2, FailureThreshold: 1,
	})
	if err != nil || again.Status != PlanStatusStaging {
		t.Fatalf("idempotent create: %v %+v", err, again)
	}
	// 同 ID 不同内容报冲突。
	_, err = svc.CreatePlan(CreatePlanInput{
		PlanID: "p1", OrderID: "o1", Nodes: []string{"n1"},
		PrecheckThreshold: 1, FailureThreshold: 1,
	})
	requireKind(t, err, KindConflict)
}

func TestCreatePlanRejectsBadInput(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1")

	cases := []CreatePlanInput{
		{OrderID: "o1", Nodes: nil, PrecheckThreshold: 1},
		{OrderID: "o1", Nodes: []string{"n1", "n1"}, PrecheckThreshold: 1},
		{OrderID: "o1", Nodes: []string{"n1"}, PrecheckThreshold: 0},
		{OrderID: "o1", Nodes: []string{"n1"}, PrecheckThreshold: 2},
		{OrderID: "o1", Nodes: []string{"n1"}, PrecheckThreshold: 1, FailureThreshold: -1},
	}
	for i, in := range cases {
		if _, err := svc.CreatePlan(in); err == nil {
			t.Fatalf("case %d should fail", i)
		} else {
			requireKind(t, err, KindValidation)
		}
	}
	_, err := svc.CreatePlan(CreatePlanInput{OrderID: "missing", Nodes: []string{"n1"}, PrecheckThreshold: 1})
	requireKind(t, err, KindNotFound)

	// 未签发的订单不能创建计划。
	mustCreate(t, svc, "o2", []string{"b.example.com"}, time.Hour)
	_, err = svc.CreatePlan(CreatePlanInput{OrderID: "o2", Nodes: []string{"n1"}, PrecheckThreshold: 1})
	requireKind(t, err, KindState)
}

func TestClaimReturnsMaterialAndBumpsExecVersion(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1")
	mustPlan(t, svc, "p1", "o1", []string{"n1"}, 1, 0)

	c1 := mustClaim(t, svc, "p1", "n1")
	if c1.Material != testMaterial() {
		t.Fatalf("claim must return secret material, got %+v", c1.Material)
	}
	if c1.ExecVersion != 1 {
		t.Fatalf("first claim exec version = %d, want 1", c1.ExecVersion)
	}
	c2 := mustClaim(t, svc, "p1", "n1")
	if c2.ExecVersion != 2 {
		t.Fatalf("re-claim must bump exec version, got %d", c2.ExecVersion)
	}

	// 旧执行版本的回执被拒绝。
	_, err := svc.ReportPrecheck(ReceiptInput{
		PlanID: "p1", NodeID: "n1", ReceiptID: "r-stale",
		CertDigest: c1.CertDigest, ExecVersion: c1.ExecVersion, Outcome: OutcomeSuccess,
	})
	requireKind(t, err, KindState)

	// 证书摘要不匹配报 auth。
	_, err = svc.ReportPrecheck(ReceiptInput{
		PlanID: "p1", NodeID: "n1", ReceiptID: "r-bad-digest",
		CertDigest: "forged", ExecVersion: c2.ExecVersion, Outcome: OutcomeSuccess,
	})
	requireKind(t, err, KindAuth)

	// 未领取的节点不能回报预检。
	mustPlan(t, svc, "p2", "o1", []string{"n9"}, 1, 0)
	_, err = svc.ReportPrecheck(ReceiptInput{
		PlanID: "p2", NodeID: "n9", ReceiptID: "r-no-claim",
		CertDigest: c1.CertDigest, ExecVersion: 0, Outcome: OutcomeSuccess,
	})
	requireKind(t, err, KindState)
}

func TestPrecheckThresholdTriggersActivating(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1")
	mustPlan(t, svc, "p1", "o1", []string{"n1", "n2", "n3"}, 2, 0)

	c1 := mustClaim(t, svc, "p1", "n1")
	r := mustPrecheck(t, svc, "p1", "n1", "r1", c1, OutcomeSuccess)
	if r.PlanStatus != PlanStatusStaging {
		t.Fatalf("below threshold must stay staging, got %s", r.PlanStatus)
	}

	// 门槛未达前不能激活。
	c2 := mustClaim(t, svc, "p1", "n2")
	_, err := svc.ReportActivation(ReceiptInput{
		PlanID: "p1", NodeID: "n2", ReceiptID: "ra-early",
		CertDigest: c2.CertDigest, ExecVersion: c2.ExecVersion, Outcome: OutcomeSuccess,
	})
	requireKind(t, err, KindState)

	r = mustPrecheck(t, svc, "p1", "n2", "r2", c2, OutcomeSuccess)
	if r.PlanStatus != PlanStatusActivating {
		t.Fatalf("reaching threshold must enter activating, got %s", r.PlanStatus)
	}
}

func TestReceiptReplayAndConflict(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1")
	mustPlan(t, svc, "p1", "o1", []string{"n1"}, 1, 0)
	c1 := mustClaim(t, svc, "p1", "n1")

	first := mustPrecheck(t, svc, "p1", "n1", "r1", c1, OutcomeSuccess)
	replay := mustPrecheck(t, svc, "p1", "n1", "r1", c1, OutcomeSuccess)
	if first.Reused || !replay.Reused {
		t.Fatalf("replay must reuse stored result: first=%+v replay=%+v", first, replay)
	}
	if replay.NodeStatus != first.NodeStatus || replay.PlanStatus != first.PlanStatus {
		t.Fatal("replayed result must equal original result")
	}

	// 同回执号不同内容报冲突。
	_, err := svc.ReportPrecheck(ReceiptInput{
		PlanID: "p1", NodeID: "n1", ReceiptID: "r1",
		CertDigest: c1.CertDigest, ExecVersion: c1.ExecVersion, Outcome: OutcomeFailure,
	})
	requireKind(t, err, KindConflict)
}

func TestFullFlowCompletesWithUniqueNotificationAndRetirement(t *testing.T) {
	svc := newTestService(t, newFakeClock())

	// 第一轮：v1 上线成为 current。
	cv1 := mustIssue(t, svc, "o1")
	mustPlan(t, svc, "p1", "o1", []string{"n1"}, 1, 0)
	c := mustClaim(t, svc, "p1", "n1")
	mustPrecheck(t, svc, "p1", "n1", "r1", c, OutcomeSuccess)
	mustActivate(t, svc, "p1", "n1", "ra1", c)

	// 第二轮：v2 全量激活后，v1 标记为待退役而非删除。
	cv2 := mustIssue(t, svc, "o2")
	plan := mustPlan(t, svc, "p2", "o2", []string{"n1", "n2"}, 2, 1)
	if plan.PrevVersionID != cv1.ID {
		t.Fatalf("plan must freeze prev version %s, got %q", cv1.ID, plan.PrevVersionID)
	}
	for _, n := range []string{"n1", "n2"} {
		cl := mustClaim(t, svc, "p2", n)
		mustPrecheck(t, svc, "p2", n, "r-"+n, cl, OutcomeSuccess)
	}
	var last *ReceiptResult
	for _, n := range []string{"n1", "n2"} {
		last = mustActivate(t, svc, "p2", n, "ra-"+n, currentClaim(t, svc, "p2", n))
	}
	if last.PlanStatus != PlanStatusCompleted {
		t.Fatalf("plan must complete, got %s", last.PlanStatus)
	}

	notifications := svc.ListNotifications()
	if len(notifications) != 2 {
		t.Fatalf("exactly one notification per plan, got %d", len(notifications))
	}
	n := notifications[1]
	if n.PlanID != "p2" || n.CertVersionID != cv2.ID || n.RetiredVersionID != cv1.ID {
		t.Fatalf("unexpected notification: %+v", n)
	}

	versions := map[string]CertVersionStatus{}
	for _, v := range svc.ListCertVersions() {
		versions[v.ID] = v.Status
	}
	if versions[cv2.ID] != CertVersionCurrent {
		t.Fatalf("new version must be current, got %s", versions[cv2.ID])
	}
	if versions[cv1.ID] != CertVersionPendingRetirement {
		t.Fatalf("old version must be pending_retirement (not deleted), got %s", versions[cv1.ID])
	}
	if svc.data.CertVersions[cv1.ID] == nil {
		t.Fatal("old version must not be deleted")
	}
}

func TestFailureThresholdPausesPlanAndResumeRecovers(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1")
	mustPlan(t, svc, "p1", "o1", []string{"n1", "n2", "n3"}, 2, 1)

	c1 := mustClaim(t, svc, "p1", "n1")
	r := mustPrecheck(t, svc, "p1", "n1", "r1", c1, OutcomeFailure)
	if r.PlanStatus != PlanStatusStaging {
		t.Fatalf("one failure within threshold, got %s", r.PlanStatus)
	}

	c2 := mustClaim(t, svc, "p1", "n2")
	r = mustPrecheck(t, svc, "p1", "n2", "r2", c2, OutcomeFailure)
	if r.PlanStatus != PlanStatusPaused {
		t.Fatalf("failures over threshold must pause, got %s", r.PlanStatus)
	}

	// 暂停期间拒绝领取与回执。
	if _, err := svc.ClaimNode("p1", "n3"); err == nil {
		t.Fatal("claim while paused must fail")
	} else {
		requireKind(t, err, KindState)
	}
	_, err := svc.ReportPrecheck(ReceiptInput{
		PlanID: "p1", NodeID: "n1", ReceiptID: "r-paused",
		CertDigest: c1.CertDigest, ExecVersion: c1.ExecVersion, Outcome: OutcomeSuccess,
	})
	requireKind(t, err, KindState)

	// 恢复后回到暂停前阶段，失败节点可重新领取恢复。
	view, err := svc.ResumePlan("p1")
	if err != nil || view.Status != PlanStatusStaging {
		t.Fatalf("resume: %v %+v", err, view)
	}
	re := mustClaim(t, svc, "p1", "n1") // failed -> claimed，失败数回落
	if re.ExecVersion != 2 {
		t.Fatalf("re-claim must bump exec version, got %d", re.ExecVersion)
	}
	r = mustPrecheck(t, svc, "p1", "n1", "r1-retry", re, OutcomeSuccess)
	if r.NodeStatus != NodeStatusPrechecked {
		t.Fatalf("recovered node must precheck, got %s", r.NodeStatus)
	}
}

func TestPauseResumeIdempotent(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1")
	mustPlan(t, svc, "p1", "o1", []string{"n1"}, 1, 0)

	view, err := svc.PausePlan("p1")
	if err != nil || view.Status != PlanStatusPaused {
		t.Fatalf("pause: %v %+v", err, view)
	}
	if _, err := svc.PausePlan("p1"); err != nil {
		t.Fatalf("repeat pause must be idempotent: %v", err)
	}
	if _, err := svc.ResumePlan("p1"); err != nil {
		t.Fatalf("resume: %v", err)
	}
	view, err = svc.ResumePlan("p1")
	if err != nil || view.Status != PlanStatusStaging {
		t.Fatalf("repeat resume must be idempotent: %v %+v", err, view)
	}
}

func TestRollbackLatchesDirectionAndTerminates(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1")
	mustPlan(t, svc, "p1", "o1", []string{"n1", "n2"}, 2, 5)

	claims := map[string]*ClaimResult{}
	for _, n := range []string{"n1", "n2"} {
		claims[n] = mustClaim(t, svc, "p1", n)
		mustPrecheck(t, svc, "p1", n, "r-"+n, claims[n], OutcomeSuccess)
	}
	mustActivate(t, svc, "p1", "n1", "ra-n1", claims["n1"])

	// n1 回退：方向闩为 rollback。
	view, err := svc.RollbackNode("p1", "n1")
	if err != nil || view.Direction != DirectionRollback {
		t.Fatalf("rollback: %v %+v", err, view)
	}

	// 并发方向的激活回执被拒绝：只有一个方向生效。
	_, err = svc.ReportActivation(ReceiptInput{
		PlanID: "p1", NodeID: "n2", ReceiptID: "ra-n2",
		CertDigest: claims["n2"].CertDigest, ExecVersion: claims["n2"].ExecVersion, Outcome: OutcomeSuccess,
	})
	requireKind(t, err, KindState)

	// 未激活节点不能回退。
	_, err = svc.RollbackNode("p1", "n2")
	requireKind(t, err, KindState)

	// 重复回退幂等；已激活节点全部回退后计划进入终态。
	if _, err := svc.RollbackNode("p1", "n1"); err != nil {
		t.Fatalf("repeat rollback must be idempotent: %v", err)
	}
	view, _ = svc.GetPlan("p1")
	if view.Status != PlanStatusRolledBack {
		t.Fatalf("all activated nodes rolled back must terminate plan, got %s", view.Status)
	}

	// 终态后新回执不能复活计划。
	_, err = svc.ReportActivation(ReceiptInput{
		PlanID: "p1", NodeID: "n2", ReceiptID: "ra-n2-late",
		CertDigest: claims["n2"].CertDigest, ExecVersion: claims["n2"].ExecVersion, Outcome: OutcomeSuccess,
	})
	requireKind(t, err, KindState)
	// 但已处理过的回执仍返回稳定的幂等结果。
	replay, err := svc.ReportActivation(ReceiptInput{
		PlanID: "p1", NodeID: "n1", ReceiptID: "ra-n1",
		CertDigest: claims["n1"].CertDigest, ExecVersion: claims["n1"].ExecVersion, Outcome: OutcomeSuccess,
	})
	if err != nil || !replay.Reused {
		t.Fatalf("processed receipt must replay stable result: %v %+v", err, replay)
	}
}

func TestOldPlanReceiptCannotReactivateRolledBackNode(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	cv1 := mustIssue(t, svc, "o1")
	mustPlan(t, svc, "p1", "o1", []string{"n1", "n2"}, 2, 5)
	for _, n := range []string{"n1", "n2"} {
		c := mustClaim(t, svc, "p1", n)
		mustPrecheck(t, svc, "p1", n, "r-"+n, c, OutcomeSuccess)
	}
	c1 := currentClaim(t, svc, "p1", "n1")
	mustActivate(t, svc, "p1", "n1", "ra1", c1)
	if _, err := svc.RollbackNode("p1", "n1"); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	// 新一轮证书与计划上线后，旧计划的回执不能让已回退节点重新激活旧证书。
	mustIssue(t, svc, "o2")
	mustPlan(t, svc, "p2", "o2", []string{"n1"}, 1, 0)
	_, err := svc.ReportActivation(ReceiptInput{
		PlanID: "p1", NodeID: "n1", ReceiptID: "ra1-late",
		CertDigest: cv1.CertDigest, ExecVersion: c1.ExecVersion, Outcome: OutcomeSuccess,
	})
	requireKind(t, err, KindState)

	view, _ := svc.GetPlan("p1")
	for _, n := range view.Nodes {
		if n.NodeID == "n1" && n.Status != NodeStatusRolledBack {
			t.Fatalf("rolled back node must stay rolled back, got %s", n.Status)
		}
	}
}

func TestConcurrentFinalActivationsEmitExactlyOneNotification(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustIssue(t, svc, "o1")
	mustPlan(t, svc, "p1", "o1", []string{"n1", "n2"}, 2, 0)
	for _, n := range []string{"n1", "n2"} {
		c := mustClaim(t, svc, "p1", n)
		mustPrecheck(t, svc, "p1", n, "r-"+n, c, OutcomeSuccess)
	}
	mustActivate(t, svc, "p1", "n1", "ra-n1", currentClaim(t, svc, "p1", "n1"))

	// n2 的“最后一个激活回执”以不同回执号并发到达：只有一个能生效。
	c2 := currentClaim(t, svc, "p1", "n2")
	const racers = 32
	var wg sync.WaitGroup
	errs := make([]error, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = svc.ReportActivation(ReceiptInput{
				PlanID: "p1", NodeID: "n2", ReceiptID: fmt.Sprintf("ra-n2-%d", i),
				CertDigest: c2.CertDigest, ExecVersion: c2.ExecVersion, Outcome: OutcomeSuccess,
			})
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
		t.Fatalf("exactly one concurrent receipt may apply, got %d", applied)
	}
	if n := len(svc.ListNotifications()); n != 1 {
		t.Fatalf("exactly one notification expected, got %d", n)
	}
	view, _ := svc.GetPlan("p1")
	if view.Status != PlanStatusCompleted {
		t.Fatalf("plan must be completed, got %s", view.Status)
	}
}

func TestDeployStateSurvivesReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	clock := newFakeClock()
	key := []byte("stable-key")

	svc, err := NewService(NewFilePersister(path), WithClock(clock.Now), WithDigestKey(key))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	cv := mustIssue(t, svc, "o1")
	mustPlan(t, svc, "p1", "o1", []string{"n1", "n2"}, 2, 0)
	c := mustClaim(t, svc, "p1", "n1")
	mustPrecheck(t, svc, "p1", "n1", "r1", c, OutcomeSuccess)

	// 模拟重启：计划、节点状态与证书版本全部恢复。
	svc2, err := NewService(NewFilePersister(path), WithClock(clock.Now), WithDigestKey(key))
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	view, err := svc2.GetPlan("p1")
	if err != nil {
		t.Fatalf("GetPlan after reload: %v", err)
	}
	if view.Status != PlanStatusStaging || view.PrecheckedCount != 1 {
		t.Fatalf("plan state not persisted: %+v", view)
	}

	// 重启后流程可继续推进直至完成。
	c2 := mustClaim(t, svc2, "p1", "n2")
	r := mustPrecheck(t, svc2, "p1", "n2", "r2", c2, OutcomeSuccess)
	if r.PlanStatus != PlanStatusActivating {
		t.Fatalf("threshold must trigger activating after reload, got %s", r.PlanStatus)
	}
	mustActivate(t, svc2, "p1", "n1", "ra-n1", currentClaim(t, svc2, "p1", "n1"))
	last := mustActivate(t, svc2, "p1", "n2", "ra-n2", currentClaim(t, svc2, "p1", "n2"))
	if last.PlanStatus != PlanStatusCompleted {
		t.Fatalf("plan must complete after reload, got %s", last.PlanStatus)
	}
	versions := map[string]CertVersionStatus{}
	for _, v := range svc2.ListCertVersions() {
		versions[v.ID] = v.Status
	}
	if versions[cv.ID] != CertVersionCurrent {
		t.Fatalf("cert version must be current, got %s", versions[cv.ID])
	}
}
