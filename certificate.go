package certificaterenewal

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"slices"
	"time"
)

// RegisterCertificateInput 注册证书版本的入参。
type RegisterCertificateInput struct {
	// CertID 由调用方提供以支持幂等注册；为空时由服务生成。
	CertID string
	// Domain 证书域名，注册后冻结。
	Domain string
	// Scopes 服务范围集合，注册后冻结。空集合或重复项会被拒绝。
	Scopes []string
	// TTL 证书有效期，到期时间为注册时刻 + TTL。
	TTL time.Duration
}

// RegisterCertificateResult 注册证书的结果。
type RegisterCertificateResult struct {
	Certificate CertView
	// Reused 为 true 表示命中幂等注册，返回的是已存在的证书。
	Reused bool
}

// RegisterCertificate 注册一个新的证书版本，初始激活阶段为 pending。
// 相同 CertID + 相同内容复用原结果；相同 CertID + 不同内容报 KindConflict。
func (s *Service) RegisterCertificate(in RegisterCertificateInput) (*RegisterCertificateResult, error) {
	domain := normalizeDomain(in.Domain)
	if domain == "" {
		return nil, newError(KindValidation, "domain is required")
	}
	scopes, err := normalizeScopes(in.Scopes)
	if err != nil {
		return nil, err
	}
	if in.TTL <= 0 {
		return nil, newError(KindValidation, "ttl must be positive")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	notAfter := now.Add(in.TTL)

	if in.CertID != "" {
		if existing := s.data.Certificates[in.CertID]; existing != nil {
			if existing.Domain == domain && slices.Equal(existing.Scopes, scopes) && existing.NotAfter.Equal(notAfter) {
				return &RegisterCertificateResult{Certificate: certView(existing), Reused: true}, nil
			}
			return nil, newError(KindConflict, "certificate %q already exists with different domain, scopes or expiry", in.CertID)
		}
	}

	id := in.CertID
	if id == "" {
		if id, err = randomID("crt"); err != nil {
			return nil, err
		}
	}

	s.data.CertSeq++
	cert := &Certificate{
		ID:        id,
		Domain:    domain,
		Scopes:    scopes,
		Stage:     StagePending,
		Seq:       s.data.CertSeq,
		NotAfter:  notAfter,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.data.Certificates[id] = cert
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return &RegisterCertificateResult{Certificate: certView(cert)}, nil
}

// AdvanceActivation 把证书推进到下一个激活阶段：pending -> canary -> partial -> full。
// 每推进一级，证书开始服务其服务范围的一个确定性前缀子集（canary 约 1/3、
// partial 约 2/3、full 全部），并成为这些范围上的当前证书。
//
// 已撤销的证书报 KindRevoked（迟到激活不能覆盖撤销状态）；
// 已过期的证书报 KindExpired；已到 full 报 KindState。
// 指针只向更新的版本移动：旧版本的迟到推进不能抢回已被新证书覆盖的范围。
func (s *Service) AdvanceActivation(certID string) (*CertView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cert := s.data.Certificates[certID]
	if cert == nil {
		return nil, newError(KindNotFound, "certificate %q not found", certID)
	}
	if cert.Revoked() {
		return nil, newError(KindRevoked, "certificate %q was revoked at %s, cannot advance activation",
			cert.ID, cert.RevokedAt.Format(time.RFC3339))
	}
	now := s.now()
	if !now.Before(cert.NotAfter) {
		return nil, newError(KindExpired, "certificate %q expired at %s", cert.ID, cert.NotAfter.Format(time.RFC3339))
	}

	var next ActivationStage
	switch cert.Stage {
	case StagePending:
		next = StageCanary
	case StageCanary:
		next = StagePartial
	case StagePartial:
		next = StageFull
	default:
		return nil, newError(KindState, "certificate %q is already fully activated", cert.ID)
	}

	before := activeScopes(cert.Scopes, cert.Stage)
	after := activeScopes(cert.Scopes, next)
	cert.Stage = next
	cert.UpdatedAt = now

	// 新覆盖的范围：仅当 incumbent 更旧（或不存在）时才接管，
	// 保证旧版本的迟到激活不能重新成为当前证书。
	for _, scope := range after {
		if slices.Contains(before, scope) {
			continue
		}
		scopes := s.data.Current[cert.Domain]
		if scopes == nil {
			scopes = make(map[string]string)
			s.data.Current[cert.Domain] = scopes
		}
		if incumbent := s.data.Certificates[scopes[scope]]; incumbent == nil || incumbent.Seq < cert.Seq {
			scopes[scope] = cert.ID
		}
	}

	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	v := certView(cert)
	return &v, nil
}

// RevokeCertificateInput 撤销证书的入参。RevocationID 是幂等号：
// 同号同内容复用原结果，同号但证书或服务范围不同报 KindConflict。
type RevokeCertificateInput struct {
	RevocationID string
	CertID       string
	// Scopes 本次撤销覆盖的服务范围；为空表示证书的全部服务范围。
	Scopes []string
}

// RevokeCertificateResult 撤销结果。
type RevokeCertificateResult struct {
	Revocation Revocation
	// Reused 为 true 表示该撤销号已处理过，本次复用原结果。
	Reused bool
}

// RevokeCertificate 撤销证书：记录撤销（证书、域名、撤销时的激活阶段、服务范围），
// 并标记证书不可再激活或使用。撤销是当前指针的终点：被撤销证书覆盖的范围
// 不会回退到旧版本，读取会明确报错而不是静默兜底。
func (s *Service) RevokeCertificate(in RevokeCertificateInput) (*RevokeCertificateResult, error) {
	if in.RevocationID == "" || in.CertID == "" {
		return nil, newError(KindValidation, "revocation id and cert id are required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cert := s.data.Certificates[in.CertID]
	if cert == nil {
		return nil, newError(KindNotFound, "certificate %q not found", in.CertID)
	}

	scopes := cert.Scopes
	if len(in.Scopes) > 0 {
		var err error
		scopes, err = normalizeScopes(in.Scopes)
		if err != nil {
			return nil, err
		}
		for _, scope := range scopes {
			if !slices.Contains(cert.Scopes, scope) {
				return nil, newError(KindValidation, "scope %q is not part of certificate %q", scope, in.CertID)
			}
		}
	}

	// 幂等检查优先：同一撤销号 + 相同内容复用原结果，证书或服务范围变化报冲突。
	contentHash := hashRevocation(in.CertID, cert.Domain, string(cert.Stage), scopes)
	if rec := s.data.Revocations[in.RevocationID]; rec != nil {
		if rec.ContentHash != contentHash {
			return nil, newError(KindConflict, "revocation %q already processed with different certificate or scopes", in.RevocationID)
		}
		return &RevokeCertificateResult{Revocation: *rec, Reused: true}, nil
	}

	if cert.Revoked() {
		return nil, newError(KindState, "certificate %q is already revoked by %q", in.CertID, cert.RevocationID)
	}

	now := s.now()
	cert.RevokedAt = &now
	cert.RevocationID = in.RevocationID
	cert.UpdatedAt = now

	rec := &Revocation{
		ID:          in.RevocationID,
		CertID:      cert.ID,
		Domain:      cert.Domain,
		Stage:       cert.Stage,
		Scopes:      slices.Clone(scopes),
		ContentHash: contentHash,
		CreatedAt:   now,
	}
	s.data.Revocations[rec.ID] = rec
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return &RevokeCertificateResult{Revocation: *rec}, nil
}

// ReadCertificateInput 服务读取证书的入参。
type ReadCertificateInput struct {
	Domain string
	Scope  string
	// KnownCertID 是调用方当前持有的证书号；为空表示首次读取。
	KnownCertID string
}

// StaleNote 说明调用方持有的证书为何不可继续使用。
type StaleNote struct {
	CertID string
	Reason string
	Detail string
}

// ReadCertificateResult 读取结果。
type ReadCertificateResult struct {
	Certificate CertView
	// Stale 非空表示 KnownCertID 已被更新版本替代，说明原因。
	Stale *StaleNote
}

// ReadCertificate 返回域名 + 服务范围上的当前有效证书。
//
//   - 当前证书已撤销：报 KindRevoked，绝不回退到更老的版本兜底；
//   - 当前证书已过期：报 KindExpired；
//   - 调用方持有的证书已撤销 / 已过期：报 KindRevoked / KindExpired；
//   - 调用方持有的证书被更新版本替代：返回当前证书，并在 Stale 中说明原因。
func (s *Service) ReadCertificate(in ReadCertificateInput) (*ReadCertificateResult, error) {
	domain := normalizeDomain(in.Domain)
	if domain == "" || in.Scope == "" {
		return nil, newError(KindValidation, "domain and scope are required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	currentID := s.data.Current[domain][in.Scope]
	if currentID == "" {
		return nil, newError(KindNotFound, "no active certificate for domain %q scope %q", domain, in.Scope)
	}
	current := s.data.Certificates[currentID]
	if current.Revoked() {
		return nil, newError(KindRevoked,
			"certificate %q for domain %q scope %q was revoked at %s; older versions cannot be restored as fallback",
			current.ID, domain, in.Scope, current.RevokedAt.Format(time.RFC3339))
	}
	if !now.Before(current.NotAfter) {
		return nil, newError(KindExpired, "certificate %q expired at %s", current.ID, current.NotAfter.Format(time.RFC3339))
	}

	res := &ReadCertificateResult{Certificate: certView(current)}
	if in.KnownCertID != "" && in.KnownCertID != current.ID {
		known := s.data.Certificates[in.KnownCertID]
		if known == nil {
			return nil, newError(KindNotFound, "certificate %q not found", in.KnownCertID)
		}
		switch {
		case known.Revoked():
			return nil, newError(KindRevoked,
				"certificate %q was revoked at %s and cannot be used; current certificate is %q",
				known.ID, known.RevokedAt.Format(time.RFC3339), current.ID)
		case !now.Before(known.NotAfter):
			return nil, newError(KindExpired, "certificate %q expired at %s; current certificate is %q",
				known.ID, known.NotAfter.Format(time.RFC3339), current.ID)
		default:
			res.Stale = &StaleNote{
				CertID: known.ID,
				Reason: "superseded",
				Detail: "replaced by newer certificate " + current.ID,
			}
		}
	}
	return res, nil
}

// GetCertificate 查询证书版本及其激活阶段。
func (s *Service) GetCertificate(certID string) (*CertView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cert := s.data.Certificates[certID]
	if cert == nil {
		return nil, newError(KindNotFound, "certificate %q not found", certID)
	}
	v := certView(cert)
	return &v, nil
}

// activeScopes 返回阶段覆盖的服务范围前缀：canary 约 1/3、partial 约 2/3、full 全部。
func activeScopes(scopes []string, stage ActivationStage) []string {
	level := stageLevel(stage)
	if level == 0 {
		return nil
	}
	n := (len(scopes)*level + 2) / 3
	if n > len(scopes) {
		n = len(scopes)
	}
	return scopes[:n]
}

// hashRevocation 计算撤销内容摘要，用于同号异内容的冲突检测。
func hashRevocation(certID, domain, stage string, scopes []string) string {
	h := sha256.New()
	for _, part := range []string{certID, domain, stage} {
		io.WriteString(h, part)
		h.Write([]byte{0})
	}
	for _, scope := range scopes {
		io.WriteString(h, scope)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func normalizeScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, newError(KindValidation, "at least one scope is required")
	}
	out := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if scope == "" {
			return nil, newError(KindValidation, "empty scope")
		}
		if _, dup := seen[scope]; dup {
			return nil, newError(KindValidation, "duplicate scope %q", scope)
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	slices.Sort(out)
	return out, nil
}

// CertView 是证书版本的对外视图。
type CertView struct {
	ID           string
	Domain       string
	Scopes       []string
	Stage        ActivationStage
	ActiveScopes []string
	NotAfter     time.Time
	CreatedAt    time.Time
	Revoked      bool
	RevokedAt    *time.Time
}

func certView(c *Certificate) CertView {
	return CertView{
		ID:           c.ID,
		Domain:       c.Domain,
		Scopes:       slices.Clone(c.Scopes),
		Stage:        c.Stage,
		ActiveScopes: slices.Clone(activeScopes(c.Scopes, c.Stage)),
		NotAfter:     c.NotAfter,
		CreatedAt:    c.CreatedAt,
		Revoked:      c.Revoked(),
		RevokedAt:    c.RevokedAt,
	}
}
