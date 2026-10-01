import { FormEvent, useEffect, useState } from 'react';
import { Activity, ArrowUpRight, Link2, ShieldCheck, ShieldAlert, LoaderCircle } from 'lucide-react';
import { AuthPage, DashboardData, DashboardPage, HistoryFilters, HistoryPage, RecentScan } from './pages';

const apiUrl = import.meta.env.VITE_API_URL ?? (import.meta.env.DEV ? 'http://localhost:8000' : '');
type Finding = { category: string; severity: string; title: string; description: string; evidence: string };
type RiskComponent = { title: string; category: string; severity: string; evidence: string; impact: number };
type DomainPart = { status: string; addresses?: string[]; reason?: string; issuer?: string | null; not_after?: string | null; days_until_expiry?: number | null; verification?: string; note?: string };
type BrandMatch = { brand: string; matched_label_similarity: number; official_domains: string[]; matched_text: string; reason: string };
type ProviderResult = { provider: string; status: string; reason?: string; malicious_count?: number; suspicious_count?: number; match_count?: number; threat_types?: string[]; checked_at?: string };
type RedirectAnalysis = { status: string; redirect_count: number; chain: { domain: string; status_code: number; redirect_to?: string }[]; final_domain?: string; domain_changed?: boolean; domains?: string[]; reason?: string };
type Scan = RecentScan & { original_url: string; normalized_url: string; summary: string; findings: Finding[]; risk_calculation: { method: string; formula: string; components: RiskComponent[]; raw_total: number; final_score: number } | null; domain_intelligence: { dns: DomainPart; certificate: DomainPart; registration: DomainPart } | null; brand_analysis: { status: string; matches: BrandMatch[]; note: string } | null; threat_intelligence: { status: string; providers: ProviderResult[]; note: string } | null; redirect_analysis: RedirectAnalysis | null; ai_explanation: { source: string; provider_status: string; summary: string; explanation: string; recommended_action: string } | null };
type User = { id: string; email: string; role: string };

function apiMessage(data: any, fallback: string) {
  if (typeof data?.detail === 'string') return data.detail;
  if (Array.isArray(data?.detail)) return data.detail.map((item: any) => item.msg).join('. ');
  return fallback;
}

export default function App() {
  const [url, setUrl] = useState('');
  const [scan, setScan] = useState<Scan | null>(null);
  const [page, setPage] = useState<'scan' | 'dashboard' | 'history' | 'auth'>('auth');
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [accessToken, setAccessToken] = useState(() => sessionStorage.getItem('linkshield_access') || '');
  const [refreshToken, setRefreshToken] = useState(() => sessionStorage.getItem('linkshield_refresh') || '');
  const [user, setUser] = useState<User | null>(null);
  const [authError, setAuthError] = useState('');
  const [authNotice, setAuthNotice] = useState('');
  const [authBusy, setAuthBusy] = useState(false);
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [dashboardError, setDashboardError] = useState('');
  const [dashboardBusy, setDashboardBusy] = useState(false);
  const [history, setHistory] = useState<RecentScan[]>([]);
  const [historyError, setHistoryError] = useState('');
  const [historyBusy, setHistoryBusy] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [platformReady, setPlatformReady] = useState<boolean | null>(null);

  function clearSession() {
    sessionStorage.removeItem('linkshield_access'); sessionStorage.removeItem('linkshield_refresh');
    setAccessToken(''); setRefreshToken(''); setUser(null);
  }

  async function apiFetch(path: string, init: RequestInit = {}) {
    const send = (token: string) => {
      const headers = new Headers(init.headers);
      if (token) headers.set('Authorization', `Bearer ${token}`);
      return fetch(`${apiUrl}${path}`, { ...init, headers });
    };
    let response = await send(accessToken);
    if (response.status !== 401 || !refreshToken) return response;
    try {
      const renewed = await fetch(`${apiUrl}/api/auth/refresh`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ refresh_token: refreshToken }) });
      if (!renewed.ok) { clearSession(); return response; }
      const tokens = await renewed.json();
      sessionStorage.setItem('linkshield_access', tokens.access_token); sessionStorage.setItem('linkshield_refresh', tokens.refresh_token);
      setAccessToken(tokens.access_token); setRefreshToken(tokens.refresh_token); setUser(tokens.user);
      response = await send(tokens.access_token);
      return response;
    } catch { clearSession(); return response; }
  }

  useEffect(() => {
    let active = true;
    fetch(`${apiUrl}/health/ready`).then(response => response.ok ? response.json() : Promise.reject())
      .then(data => { if (active) setPlatformReady(data.status === 'ready'); })
      .catch(() => { if (active) setPlatformReady(false); });
    if (accessToken) apiFetch('/api/auth/me').then(async response => {
      if (!active) return;
      if (response.ok) { setUser(await response.json()); setPage('dashboard'); }
      else clearSession();
    }).catch(() => { if (active) clearSession(); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (page !== 'dashboard' || !accessToken) return;
    let active = true; setDashboardBusy(true); setDashboardError('');
    apiFetch('/api/dashboard/stats').then(async response => {
      const data = await response.json();
      if (!response.ok) throw new Error(apiMessage(data, 'Could not load dashboard data.'));
      if (active) setDashboard(data);
    }).catch(cause => { if (active) setDashboardError(cause instanceof Error ? cause.message : 'Could not load dashboard data.'); })
      .finally(() => { if (active) setDashboardBusy(false); });
    return () => { active = false; };
  }, [page, accessToken]);

  async function loadHistory(filters?: HistoryFilters) {
    setHistoryBusy(true); setHistoryError('');
    const query = new URLSearchParams({ limit: '100' });
    if (filters) Object.entries(filters).forEach(([key, value]) => { if (value) query.set(key, value); });
    try {
      const response = await apiFetch(`/api/scans?${query.toString()}`);
      const data = await response.json();
      if (!response.ok) throw new Error(apiMessage(data, 'Could not load scan history.'));
      setHistory(data);
    } catch (cause) { setHistoryError(cause instanceof Error ? cause.message : 'Could not load scan history.'); }
    finally { setHistoryBusy(false); }
  }

  useEffect(() => { if (page === 'history' && accessToken) void loadHistory(); }, [page, accessToken]);

  function openPrivatePage(target: 'dashboard' | 'history') {
    if (!accessToken || !user) { setAuthError('Sign in or create an account to view private scans and dashboard data.'); setPage('auth'); return; }
    setPage(target);
  }

  async function authenticate(email: string, password: string) {
    setAuthBusy(true); setAuthError(''); setAuthNotice('');
    try {
      const endpoint = authMode === 'login' ? 'login' : 'register';
      const response = await fetch(`${apiUrl}/api/auth/${endpoint}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
      const data = await response.json();
      if (!response.ok) throw new Error(apiMessage(data, authMode === 'login' ? 'Could not sign in.' : 'Could not create your account.'));
      if (authMode === 'register') {
        setAuthMode('login');
        setAuthNotice('Your account was created. Sign in with your new account to continue.');
        return;
      }
      sessionStorage.setItem('linkshield_access', data.access_token); sessionStorage.setItem('linkshield_refresh', data.refresh_token);
      setAccessToken(data.access_token); setRefreshToken(data.refresh_token); setUser(data.user); setPage('dashboard'); setAuthError('');
    } catch (cause) { setAuthError(cause instanceof Error ? cause.message : 'Could not reach the authentication service.'); }
    finally { setAuthBusy(false); }
  }

  async function signOut() {
    if (refreshToken) void fetch(`${apiUrl}/api/auth/logout`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ refresh_token: refreshToken }) }).catch(() => undefined);
    clearSession(); setDashboard(null); setHistory([]); setPage('auth'); setAuthMode('login');
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setLoading(true); setError(''); setScan(null);
    try {
      const response = await apiFetch('/api/scans', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
      const data = await response.json();
      if (!response.ok) throw new Error(apiMessage(data, 'The URL could not be analyzed.'));
      setScan(data);
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'The API could not be reached.'); }
    finally { setLoading(false); }
  }

  async function viewScan(id: string) {
    try {
      const response = await apiFetch(`/api/scans/${id}`); const data = await response.json();
      if (!response.ok) throw new Error(apiMessage(data, 'Could not load this scan.'));
      setScan(data); setPage('scan');
    } catch (cause) { setHistoryError(cause instanceof Error ? cause.message : 'Could not load this scan.'); }
  }

  return <main className="shell">
    <header className="topbar"><a className="brand" href="#" onClick={e => { e.preventDefault(); setPage(user ? 'scan' : 'auth'); }}>LinkShield</a>
      {user && <nav className="primary-nav" aria-label="Main navigation"><button className={page === 'scan' ? 'active' : ''} onClick={() => setPage('scan')}>Scan</button><button className={page === 'dashboard' ? 'active' : ''} onClick={() => openPrivatePage('dashboard')}>Dashboard</button><button className={page === 'history' ? 'active' : ''} onClick={() => openPrivatePage('history')}>History</button></nav>}
      <span className="header-status"><i/> {user ? user.email : 'Protection workspace'}</span>{user ? <button className="auth-trigger" onClick={signOut}>Sign out</button> : <button className="auth-trigger" onClick={() => { setAuthMode('login'); setPage('auth'); }}>Sign in</button>}
    </header>
    {page === 'scan' && <section className="hero">
      <div className="eyebrow"><span/> LINK INTELLIGENCE</div><h1>Pause before<br/><em>you click.</em></h1>
      <p className="intro">Check a suspicious link for risk signals before opening it. We assess available evidence; no scan can guarantee a link is safe.</p>
      <form className="scan-card" onSubmit={submit}>
        <label htmlFor="url">URL TO INSPECT</label><div className="input-row"><Link2 size={19}/><input id="url" value={url} onChange={event => setUrl(event.target.value)} placeholder="Paste a suspicious link here…" autoComplete="url"/><button disabled={!url.trim() || loading}>{loading ? <><LoaderCircle className="spin" size={15}/> Checking</> : <>Analyze link <ArrowUpRight size={16}/></>}</button></div>
        <div className="safe-note"><ShieldAlert size={14}/> LinkShield does not render or download pages. Redirect checks may send bounded HEAD requests to public hosts; configured threat providers receive the redacted URL. Optional AI receives only the score and signal labels.</div>{error && <p className="error" role="alert">{error}</p>}
      </form>
      {scan && <section className="result-card" aria-live="polite">
        <div className="result-head"><div><small>DETERMINISTIC RISK ASSESSMENT</small><h2>Review complete</h2></div><span className="domain-pill">{scan.domain}</span></div>
        <div className="risk-overview"><div className="risk-number"><strong>{scan.risk_score ?? '—'}</strong><span>/100</span></div><span className={`risk-level ${(scan.risk_level || 'unknown').toLowerCase()}`}>{scan.risk_level || 'UNASSESSED'} RISK</span><div className="risk-meter" role="meter" aria-label="Risk score" aria-valuemin={0} aria-valuemax={100} aria-valuenow={scan.risk_score ?? 0}><span style={{ width: `${scan.risk_score ?? 0}%` }}/></div></div>
        <p className="result-summary">{scan.summary}</p>
        {scan.ai_explanation && <article className="score-details ai-explanation"><div className="panel-heading"><h3>Why this result matters</h3><span>{scan.ai_explanation.source === 'ai' ? 'AI EXPLANATION' : 'BUILT-IN EXPLANATION'}</span></div><strong>{scan.ai_explanation.summary}</strong><p>{scan.ai_explanation.explanation}</p><p><b>Suggested next step:</b> {scan.ai_explanation.recommended_action}</p><small>AI explanations help describe the findings; they never set or change the risk score. When enabled, the provider receives the score and signal labels only—not the submitted URL or evidence.</small></article>}
        {scan.risk_calculation && <details className="score-details"><summary>How the score was calculated</summary><p>{scan.risk_calculation.method}</p><code>{scan.risk_calculation.formula}</code><div className="contribution-list">{scan.risk_calculation.components.map((component, index) => <div className="contribution" key={`${component.title}-${index}`}><span>{component.title}<small>{component.evidence}</small></span><b className={component.impact < 0 ? 'offset' : ''}>{component.impact > 0 ? '+' : ''}{component.impact}</b></div>)}</div></details>}
        <p className="normalized">Normalized address: <code>{scan.normalized_url}</code></p>
        {scan.findings.length ? <div className="finding-list">{scan.findings.map((finding, index) => <article className="finding" key={`${finding.title}-${index}`}><span className={`severity ${finding.severity.toLowerCase()}`}>{finding.severity}</span><div><strong>{finding.title}</strong><p>{finding.description}</p><small>{finding.evidence}</small></div></article>)}</div> : <p className="no-findings">No URL-structure indicators were found. That does not confirm the link is safe.</p>}
        {scan.domain_intelligence && <details className="score-details domain-details"><summary>Domain intelligence</summary><div className="contribution-list"><div className="contribution"><span>DNS addresses<small>{scan.domain_intelligence.dns.addresses?.join(', ') || scan.domain_intelligence.dns.reason || 'No public DNS result available.'}</small></span><b>{scan.domain_intelligence.dns.status}</b></div><div className="contribution"><span>TLS certificate<small>{scan.domain_intelligence.certificate.issuer || scan.domain_intelligence.certificate.reason || scan.domain_intelligence.certificate.note || 'No certificate details available.'}{scan.domain_intelligence.certificate.not_after ? ` · expires ${scan.domain_intelligence.certificate.not_after}` : ''}</small></span><b>{scan.domain_intelligence.certificate.status}</b></div><div className="contribution"><span>Domain registration age<small>{scan.domain_intelligence.registration.reason || 'No registration date available; age was not inferred.'}</small></span><b>{scan.domain_intelligence.registration.status}</b></div></div><p>DNS and certificate metadata are observational signals. Certificate trust validation is not performed here.</p></details>}
        {scan.brand_analysis && <details className="score-details"><summary>Brand impersonation review</summary>{scan.brand_analysis.matches.length ? <div className="contribution-list">{scan.brand_analysis.matches.map(match => <div className="contribution" key={match.brand}><span>{match.brand}<small>{match.reason} Matched hostname text: {match.matched_text}; configured official domains: {match.official_domains.join(', ')}</small></span><b>{Math.round(match.matched_label_similarity * 100)}% matched-label similarity</b></div>)}</div> : <p>No configured brand resemblance was found. That does not establish trustworthiness.</p>}<p>{scan.brand_analysis.note}</p></details>}
        {scan.threat_intelligence && <details className="score-details"><summary>Threat intelligence · {scan.threat_intelligence.status}</summary><div className="contribution-list">{scan.threat_intelligence.providers.map(provider => <div className="contribution" key={provider.provider}><span>{provider.provider}<small>{provider.reason || (provider.threat_types?.length ? `Threat types: ${provider.threat_types.join(', ')}` : provider.checked_at ? `Checked ${provider.checked_at}` : 'No provider details returned.')}</small></span><b>{provider.status}</b></div>)}</div><p>{scan.threat_intelligence.note}</p></details>}
        {scan.redirect_analysis && <details className="score-details"><summary>Redirect analysis · {scan.redirect_analysis.status}</summary><div className="contribution-list">{scan.redirect_analysis.chain.map((hop, index) => <div className="contribution" key={`${hop.domain}-${index}`}><span>{hop.domain}<small>HTTP status {hop.status_code}{hop.redirect_to ? ` · redirects to ${hop.redirect_to}` : ''}</small></span><b>{index + 1}</b></div>)}</div><p>{scan.redirect_analysis.reason || `${scan.redirect_analysis.redirect_count} redirect(s); final host ${scan.redirect_analysis.final_domain || scan.domain}. Redirect checks send HEAD requests only and do not download page content.`}</p></details>}
        <p className="phase-note">Risk includes URL structure, configured brand-similarity indicators, confirmed provider matches, and multiple redirects. DNS and certificate details are observational; registration age is unavailable without a provider. A low score does not guarantee safety.</p>
      </section>}
    </section>}
    {page === 'auth' && <AuthPage mode={authMode} busy={authBusy} error={authError} notice={authNotice} onSubmit={authenticate} onToggle={() => { setAuthMode(authMode === 'login' ? 'register' : 'login'); setAuthError(''); setAuthNotice(''); }} />}
    {page === 'dashboard' && <DashboardPage data={dashboard} busy={dashboardBusy} error={dashboardError} onOpenHistory={() => openPrivatePage('history')} onViewScan={viewScan} onNewScan={() => setPage('scan')}/>}
    {page === 'history' && <HistoryPage rows={history} busy={historyBusy} error={historyError} onSearch={filters => void loadHistory(filters)} onViewScan={viewScan}/>}
    <section className="status-grid"><article className="status-card"><span className="card-icon"><Activity size={17}/></span><div><small>PLATFORM STATUS</small><strong>{platformReady === null ? 'Checking services…' : platformReady ? 'Services ready' : 'API unavailable'}</strong></div><span className={`pulse ${platformReady === false ? 'offline' : ''}`}/></article><article className="status-card"><span className="card-icon blue"><ShieldCheck size={17}/></span><div><small>ANALYSIS ENGINE</small><strong>Scan dashboard</strong></div><span className="dim">PHASE 10</span></article></section>
    <footer><span>LINKSHIELD <b>·</b> SECURITY THROUGH CLARITY</span><span>CREATED BY SANJAY S</span><span>Risk assessment, not a guarantee · API <a href={`${apiUrl}/health`}>health <ArrowUpRight size={11}/></a></span></footer>
  </main>;
}
