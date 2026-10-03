package certificaterenewal

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func mustRegister(t *testing.T, svc *Service, id, domain string, scopes []string, ttl time.Duration) *RegisterCertificateResult {
	t.Helper()
	res, err := svc.RegisterCertificate(RegisterCertificateInput{
		CertID: id, Domain: domain, Scopes: scopes, TTL: ttl,
	})
	if err != nil {
		t.Fatalf("RegisterCertificate(%s): %v", id, err)
	}
	return res
}

func mustAdvance(t *testing.T, svc *Service, certID string) *CertView {
	t.Helper()
	view, err := svc.AdvanceActivation(certID)
	if err != nil {
		t.Fatalf("AdvanceActivation(%s): %v", certID, err)
	}
	return view
}

func mustRead(t *testing.T, svc *Service, domain, scope, known string) *ReadCertificateResult {
	t.Helper()
	res, err := svc.ReadCertificate(ReadCertificateInput{Domain: domain, Scope: scope, KnownCertID: known})
	if err != nil {
		t.Fatalf("ReadCertificate(%s/%s): %v", domain, scope, err)
	}
	return res
}

func TestRegisterCertificateIdempotent(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	scopes := []string{"web", "api"}

	first := mustRegister(t, svc, "c1", "a.example.com", scopes, time.Hour)
	second, err := svc.RegisterCertificate(RegisterCertificateInput{
		CertID: "c1", Domain: "a.example.com", Scopes: scopes, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("idempotent register: %v", err)
	}
	if first.Reused || !second.Reused {
		t.Fatalf("first.Reused=%v second.Reused=%v", first.Reused, second.Reused)
	}

	_, err = svc.RegisterCertificate(RegisterCertificateInput{
		CertID: "c1", Domain: "a.example.com", Scopes: []string{"other"}, TTL: time.Hour,
	})
	requireKind(t, err, KindConflict)
}

func TestStagedActivationPartialSwitchover(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	scopes := []string{"api", "edge", "web"}

	mustRegister(t, svc, "c1", "a.example.com", scopes, time.Hour)
	mustAdvance(t, svc, "c1")
	mustAdvance(t, svc, "c1")
	full := mustAdvance(t, svc, "c1")
	if full.Stage != StageFull || len(full.ActiveScopes) != 3 {
		t.Fatalf("c1 should be fully activated, got %+v", full)
	}
	requireKind(t, advanceErr(svc, "c1"), KindState)

	// 新版本分阶段切换：canary 只接管第一个范围，其余仍由旧版本服务。
	mustRegister(t, svc, "c2", "a.example.com", scopes, time.Hour)
	canary := mustAdvance(t, svc, "c2")
	if fmt.Sprint(canary.ActiveScopes) != fmt.Sprint([]string{"api"}) {
		t.Fatalf("canary active scopes = %v", canary.ActiveScopes)
	}
	if got := mustRead(t, svc, "a.example.com", "api", "").Certificate.ID; got != "c2" {
		t.Fatalf("scope api should be served by c2, got %s", got)
	}
	for _, scope := range []string{"edge", "web"} {
		if got := mustRead(t, svc, "a.example.com", scope, "").Certificate.ID; got != "c1" {
			t.Fatalf("scope %s should still be served by c1, got %s", scope, got)
		}
	}

	partial := mustAdvance(t, svc, "c2")
	if fmt.Sprint(partial.ActiveScopes) != fmt.Sprint([]string{"api", "edge"}) {
		t.Fatalf("partial active scopes = %v", partial.ActiveScopes)
	}
	if got := mustRead(t, svc, "a.example.com", "web", "").Certificate.ID; got != "c1" {
		t.Fatalf("scope web should still be served by c1, got %s", got)
	}

	mustAdvance(t, svc, "c2")
	for _, scope := range scopes {
		if got := mustRead(t, svc, "a.example.com", scope, "").Certificate.ID; got != "c2" {
			t.Fatalf("scope %s should be served by c2, got %s", scope, got)
		}
	}
}

func TestLateActivationCannotStealScopeBack(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	scopes := []string{"api", "edge", "web"}

	mustRegister(t, svc, "c1", "a.example.com", scopes, time.Hour)
	mustAdvance(t, svc, "c1") // canary: api
	mustRegister(t, svc, "c2", "a.example.com", scopes, time.Hour)
	mustAdvance(t, svc, "c2")
	mustAdvance(t, svc, "c2")
	mustAdvance(t, svc, "c2") // full: 全部范围归 c2

	// 旧版本的迟到推进不能抢回已被新证书覆盖的范围。
	mustAdvance(t, svc, "c1") // partial
	mustAdvance(t, svc, "c1") // full
	for _, scope := range scopes {
		if got := mustRead(t, svc, "a.example.com", scope, "").Certificate.ID; got != "c2" {
			t.Fatalf("scope %s should stay with newer c2, got %s", scope, got)
		}
	}
}

func TestRevokeCertificateRecordsDetails(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustRegister(t, svc, "c1", "a.example.com", []string{"api", "web"}, time.Hour)
	mustAdvance(t, svc, "c1")

	res, err := svc.RevokeCertificate(RevokeCertificateInput{RevocationID: "rev-1", CertID: "c1"})
	if err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	rec := res.Revocation
	if res.Reused {
		t.Fatal("first revocation should not be reused")
	}
	if rec.CertID != "c1" || rec.Domain != "a.example.com" || rec.Stage != StageCanary {
		t.Fatalf("revocation record mismatch: %+v", rec)
	}
	if fmt.Sprint(rec.Scopes) != fmt.Sprint([]string{"api", "web"}) {
		t.Fatalf("revocation scopes = %v", rec.Scopes)
	}

	view, err := svc.GetCertificate("c1")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if !view.Revoked || view.RevokedAt == nil {
		t.Fatalf("certificate should be marked revoked: %+v", view)
	}
}

func TestRevokeCertificateDuplicateAndConflict(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	mustRegister(t, svc, "c1", "a.example.com", []string{"api", "web"}, time.Hour)
	mustRegister(t, svc, "c2", "a.example.com", []string{"api", "web"}, time.Hour)

	first, err := svc.RevokeCertificate(RevokeCertificateInput{RevocationID: "rev-1", CertID: "c1"})
	if err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}

	// 相同撤销请求返回原结果。
	replay, err := svc.RevokeCertificate(RevokeCertificateInput{RevocationID: "rev-1", CertID: "c1"})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !replay.Reused || replay.Revocation.CertID != first.Revocation.CertID ||
		!replay.Revocation.CreatedAt.Equal(first.Revocation.CreatedAt) {
		t.Fatalf("replay must return original result: %+v", replay)
	}

	// 证书或服务范围变化返回冲突。
	_, err = svc.RevokeCertificate(RevokeCertificateInput{RevocationID: "rev-1", CertID: "c2"})
	requireKind(t, err, KindConflict)
	_, err = svc.RevokeCertificate(RevokeCertificateInput{RevocationID: "rev-1", CertID: "c1", Scopes: []string{"api"}})
	requireKind(t, err, KindConflict)

	// 换撤销号重复撤销同一证书报 state。
	_, err = svc.RevokeCertificate(RevokeCertificateInput{RevocationID: "rev-2", CertID: "c1"})
	requireKind(t, err, KindState)
}

func TestRevokedCurrentNeverFallsBackToOlderVersion(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	scopes := []string{"api"}

	mustRegister(t, svc, "c1", "a.example.com", scopes, time.Hour)
	mustAdvance(t, svc, "c1")
	mustAdvance(t, svc, "c1")
	mustAdvance(t, svc, "c1")
	mustRegister(t, svc, "c2", "a.example.com", scopes, time.Hour)
	mustAdvance(t, svc, "c2")
	mustAdvance(t, svc, "c2")
	mustAdvance(t, svc, "c2")

	if _, err := svc.RevokeCertificate(RevokeCertificateInput{RevocationID: "rev-1", CertID: "c2"}); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}

	// 当前证书被撤销后不能静默回退到更老的 c1。
	_, err := svc.ReadCertificate(ReadCertificateInput{Domain: "a.example.com", Scope: "api"})
	requireKind(t, err, KindRevoked)

	// 迟到激活不能覆盖撤销状态。
	requireKind(t, advanceErr(svc, "c2"), KindRevoked)
	view, err := svc.GetCertificate("c2")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if view.Stage != StageFull || !view.Revoked {
		t.Fatalf("revoked certificate must not change stage: %+v", view)
	}
}

func TestReadCertificateExplainsStaleKnownCert(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	scopes := []string{"api"}

	mustRegister(t, svc, "c1", "a.example.com", scopes, time.Hour)
	for i := 0; i < 3; i++ {
		mustAdvance(t, svc, "c1")
	}
	mustRegister(t, svc, "c2", "a.example.com", scopes, time.Hour)
	for i := 0; i < 3; i++ {
		mustAdvance(t, svc, "c2")
	}

	// 持有被替代的旧版本：返回当前证书并说明原因。
	res := mustRead(t, svc, "a.example.com", "api", "c1")
	if res.Certificate.ID != "c2" {
		t.Fatalf("current = %s, want c2", res.Certificate.ID)
	}
	if res.Stale == nil || res.Stale.CertID != "c1" || res.Stale.Reason != "superseded" {
		t.Fatalf("stale note should explain supersession: %+v", res.Stale)
	}

	// 持有已撤销的版本：明确报错，不能继续用。
	if _, err := svc.RevokeCertificate(RevokeCertificateInput{RevocationID: "rev-1", CertID: "c1"}); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	_, err := svc.ReadCertificate(ReadCertificateInput{Domain: "a.example.com", Scope: "api", KnownCertID: "c1"})
	requireKind(t, err, KindRevoked)

	// 持有不存在的版本。
	_, err = svc.ReadCertificate(ReadCertificateInput{Domain: "a.example.com", Scope: "api", KnownCertID: "ghost"})
	requireKind(t, err, KindNotFound)
}

func TestCertificateExpiry(t *testing.T) {
	clock := newFakeClock()
	svc := newTestService(t, clock)
	mustRegister(t, svc, "c1", "a.example.com", []string{"api"}, time.Hour)
	mustAdvance(t, svc, "c1")

	clock.Advance(2 * time.Hour)

	_, err := svc.ReadCertificate(ReadCertificateInput{Domain: "a.example.com", Scope: "api"})
	requireKind(t, err, KindExpired)
	requireKind(t, advanceErr(svc, "c1"), KindExpired)
}

func TestActivationRevocationReadRace(t *testing.T) {
	svc := newTestService(t, newFakeClock())
	scopes := []string{"api", "edge", "web"}
	mustRegister(t, svc, "c1", "a.example.com", scopes, time.Hour)

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers*4)

	// 激活推进：只允许推进到 full，多余推进报 state，撤销后报 revoked。
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				if err := advanceErr(svc, "c1"); err != nil {
					if kind, ok := KindOf(err); !ok || (kind != KindState && kind != KindRevoked) {
						errs <- fmt.Errorf("advance: %w", err)
					}
				}
			}
		}()
	}
	// 撤销确认：重复撤销必须幂等或报 state，不得出现其他错误。
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := fmt.Sprintf("rev-%d", n%2) // 两个撤销号并发竞争
			if _, err := svc.RevokeCertificate(RevokeCertificateInput{RevocationID: id, CertID: "c1"}); err != nil {
				if kind, ok := KindOf(err); !ok || (kind != KindState && kind != KindConflict) {
					errs <- fmt.Errorf("revoke: %w", err)
				}
			}
		}(i)
	}
	// 服务读取：只允许拿到当前有效版本或明确的分类错误。
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			scope := scopes[n%len(scopes)]
			res, err := svc.ReadCertificate(ReadCertificateInput{Domain: "a.example.com", Scope: scope})
			if err != nil {
				if _, ok := KindOf(err); !ok {
					errs <- fmt.Errorf("read: %w", err)
				}
				return
			}
			if res.Certificate.ID != "c1" || res.Certificate.Revoked {
				errs <- fmt.Errorf("read returned unusable certificate: %+v", res.Certificate)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	// 竞争结束后状态必须自洽：已撤销则阶段不再变化，且读取报 revoked。
	view, err := svc.GetCertificate("c1")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if !view.Revoked {
		t.Fatal("certificate should be revoked after concurrent revocations")
	}
	requireKind(t, advanceErr(svc, "c1"), KindRevoked)
	after, err := svc.GetCertificate("c1")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if after.Stage != view.Stage {
		t.Fatalf("revoked certificate stage changed: %s -> %s", view.Stage, after.Stage)
	}
}

func advanceErr(svc *Service, certID string) error {
	_, err := svc.AdvanceActivation(certID)
	return err
}
