import { FormEvent, useEffect, useState } from 'react';
import { Activity, ArrowRight, BarChart3, Eye, EyeOff, Fingerprint, Link2, Search, ShieldAlert, ShieldCheck, Sparkles } from 'lucide-react';

export type RecentScan = { scan_id: string; domain: string; normalized_url?: string; risk_score: number | null; risk_level: string | null; status: string; created_at: string };
export type DashboardData = {
  total_scans: number;
  high_risk_links: number;
  risk_counts: Record<string, number>;
  scans_over_time: { date: string; count: number }[];
  top_detected_brands: { label: string; count: number }[];
  threat_categories: { label: string; count: number }[];
  recent_scans: RecentScan[];
};
export type HistoryFilters = { risk_level: string; domain: string; brand: string; date_from: string; date_to: string };

function metricDate(value: string) { return new Date(value).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }); }

export function AuthPage({ mode, busy, error, notice, onSubmit, onToggle }: {
  mode: 'login' | 'register'; busy: boolean; error: string; notice: string;
  onSubmit: (email: string, password: string) => void; onToggle: () => void;
}) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [confirm, setConfirm] = useState('');
  const [showConfirm, setShowConfirm] = useState(false);
  const [localError, setLocalError] = useState('');
  useEffect(() => {
    setPassword(''); setConfirm(''); setShowPassword(false); setShowConfirm(false); setLocalError('');
  }, [mode]);
  function submit(event: FormEvent) {
    event.preventDefault(); setLocalError('');
    if (mode === 'register' && password !== confirm) { setLocalError('The passwords do not match.'); return; }
    onSubmit(email, password);
  }
  return <section className="workspace auth-panel"><div className="page-heading"><small>ACCOUNT ACCESS</small><h2>{mode === 'login' ? 'Sign in to LinkShield' : 'Create your workspace account'}</h2><p>Your scan history and dashboard are private to your account.</p></div>
    <form className="auth-form" onSubmit={submit}><label>Email<input type="email" autoComplete="email" value={email} onChange={e => setEmail(e.target.value)} required /></label><label>Password<div className="password-control"><input type={showPassword ? 'text' : 'password'} autoComplete={mode === 'login' ? 'current-password' : 'new-password'} value={password} onChange={e => setPassword(e.target.value)} minLength={mode === 'register' ? 12 : 1} maxLength={72} required /><button type="button" className="password-toggle" aria-label={showPassword ? 'Hide password' : 'Show password'} aria-pressed={showPassword} onClick={() => setShowPassword(value => !value)}>{showPassword ? <EyeOff size={16}/> : <Eye size={16}/>}</button></div>{mode === 'register' && <small>Use at least 12 characters.</small>}</label>{mode === 'register' && <label>Confirm password<div className="password-control"><input type={showConfirm ? 'text' : 'password'} autoComplete="new-password" value={confirm} onChange={e => setConfirm(e.target.value)} minLength={12} maxLength={72} required /><button type="button" className="password-toggle" aria-label={showConfirm ? 'Hide confirm password' : 'Show confirm password'} aria-pressed={showConfirm} onClick={() => setShowConfirm(value => !value)}>{showConfirm ? <EyeOff size={16}/> : <Eye size={16}/>}</button></div></label>}
      {(localError || error) && <p className="error" role="alert">{localError || error}</p>}{notice && mode === 'login' && <p className="success" role="status">{notice}</p>}<button className="primary-button" disabled={busy}>{busy ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'}</button></form>
    <p className="auth-switch">{mode === 'login' ? 'New to LinkShield?' : 'Already have an account?'} <button onClick={onToggle}>{mode === 'login' ? 'Create an account' : 'Sign in instead'}</button></p>
  </section>;
}

export function DashboardPage({ data, busy, error, onOpenHistory, onViewScan, onNewScan }: {
  data: DashboardData | null; busy: boolean; error: string;
  onOpenHistory: () => void; onViewScan: (id: string) => void; onNewScan: () => void;
}) {
  if (busy) return <section className="workspace"><p className="page-state">Loading your dashboard…</p></section>;
  if (error) return <section className="workspace"><p className="error" role="alert">{error}</p></section>;
  if (!data) return null;
  const risks = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const riskColors: Record<string, string> = { CRITICAL: '#ec6b82', HIGH: '#f19a59', MEDIUM: '#e8bb61', LOW: '#43c994' };
  let cursor = 0;
  const riskStops = risks.map(level => {
    const start = cursor;
    cursor += data.total_scans ? (data.risk_counts[level] || 0) / data.total_scans * 100 : 0;
    return `${riskColors[level]} ${start}% ${cursor}%`;
  });
  const riskRing = data.total_scans ? `conic-gradient(${riskStops.join(', ')})` : 'conic-gradient(#253449 0% 100%)';
  const timelineCounts = new Map(data.scans_over_time.map(point => [point.date, point.count]));
  const today = new Date();
  const timeline = Array.from({ length: 30 }, (_, index) => {
    const day = new Date(today);
    day.setDate(today.getDate() - 29 + index);
    const date = `${day.getFullYear()}-${String(day.getMonth() + 1).padStart(2, '0')}-${String(day.getDate()).padStart(2, '0')}`;
    return { date, count: timelineCounts.get(date) || 0 };
  });
  const maxTimeline = Math.max(1, ...timeline.map(point => point.count));
  const maxBrand = Math.max(1, ...data.top_detected_brands.map(item => item.count));
  const brandTotal = data.top_detected_brands.reduce((sum, item) => sum + item.count, 0);
  const signalTotal = data.threat_categories.reduce((sum, item) => sum + item.count, 0);
  const attentionScans = data.recent_scans.filter(scan => ['HIGH', 'CRITICAL'].includes((scan.risk_level || '').toUpperCase())).slice(0, 3);
  const titleCase = (value: string) => value.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, letter => letter.toUpperCase());
  return <section className="workspace dashboard-page">
    <section className="dashboard-hero">
      <div className="dash-hero-copy"><span className="dash-pill"><i/> ACCOUNT OVERVIEW</span><h2>Your links,<br/><em>under watch.</em></h2><p>Track what you’ve checked and spot the patterns worth a second look.</p><button className="dashboard-scan-button" onClick={onNewScan}><Link2 size={15}/> Scan a link <ArrowRight size={14}/></button></div>
      <div className="hero-visual" aria-hidden="true"><span className="hero-orbit hero-orbit-one"/><span className="hero-orbit hero-orbit-two"/><span className="hero-orbit hero-orbit-three"/><div className="hero-shield"><ShieldCheck size={43}/></div><span className="hero-tag hero-tag-one"><Activity size={13}/> Signal analysis</span><span className="hero-tag hero-tag-two"><Fingerprint size={13}/> Brand checks</span><span className="hero-tag hero-tag-three"><ShieldAlert size={13}/> Link review</span><i className="hero-spark hero-spark-one"/><i className="hero-spark hero-spark-two"/></div>
      <div className="hero-caption">LINKSHIELD <b>·</b> SECURITY THROUGH CLARITY <span>YOUR PRIVATE WORKSPACE</span></div>
    </section>
    <div className="metric-grid">
      <article className="metric-card metric-scans"><div className="metric-icon"><Activity size={17}/></div><small>TOTAL SCANS</small><strong>{data.total_scans}</strong><span>Saved assessments</span></article>
      <article className="metric-card metric-attention"><div className="metric-icon"><ShieldAlert size={17}/></div><small>HIGH / CRITICAL</small><strong>{data.high_risk_links}</strong><span>Worth a closer look</span></article>
      <article className="metric-card metric-brands"><div className="metric-icon"><Fingerprint size={17}/></div><small>BRANDS FLAGGED</small><strong>{brandTotal}</strong><span>Lookalike indicators</span></article>
      <article className="metric-card metric-signals"><div className="metric-icon"><ShieldCheck size={17}/></div><small>THREAT SIGNALS</small><strong>{signalTotal}</strong><span>Recorded findings</span></article>
    </div>
    <div className="dashboard-grid">
      <article className="data-panel risk-panel"><div className="panel-heading"><div><small className="panel-kicker">YOUR SCAN MIX</small><h3>Risk distribution</h3></div><BarChart3 size={17}/></div><div className="risk-distribution"><div className="risk-donut" style={{ background: riskRing }}><div><strong>{data.total_scans}</strong><span>scans</span></div></div><div className="risk-legend">{risks.map(level => { const count = data.risk_counts[level] || 0; const percent = data.total_scans ? Math.round(count / data.total_scans * 100) : 0; return <div className="risk-legend-row" key={level}><i className={`legend-dot ${level.toLowerCase()}`}/><span>{titleCase(level)}</span><b>{count}</b><small>{percent}%</small></div>; })}</div></div></article>
      <article className="data-panel brand-panel"><div className="panel-heading"><div><small className="panel-kicker">IMPERSONATION SIGNALS</small><h3>Top detected brands</h3></div><Fingerprint size={17}/></div>{data.top_detected_brands.length ? <div className="brand-bars">{data.top_detected_brands.slice(0, 5).map(item => <div className="brand-bar-row" key={item.label}><span>{item.label}</span><div className="bar-track"><i className="bar-fill brand-fill" style={{ width: `${item.count / maxBrand * 100}%` }}/></div><b>{item.count}</b></div>)}</div> : <p className="empty-state">No brand lookalike signals yet. Your scans will appear here.</p>}<div className="panel-footnote">A brand signal is a review cue, not proof of impersonation.</div></article>
      <article className="data-panel timeline-panel"><div className="panel-heading"><div><small className="panel-kicker">LAST 30 DAYS</small><h3>Scan activity</h3></div><span className="activity-total"><Activity size={14}/>{data.scans_over_time.reduce((sum, point) => sum + point.count, 0)} scans</span></div><div className="timeline-chart"><div className="timeline-bars" role="img" aria-label="Daily scan activity for the last 30 days">{timeline.map((point, index) => <div className={`timeline-column ${point.count ? 'has-scans' : ''}`} key={point.date} title={`${point.date}: ${point.count} scan(s)`}><span style={{ height: `${point.count ? Math.max(12, point.count / maxTimeline * 100) : 2}%` }}/>{(index === 0 || index === 7 || index === 14 || index === 21 || index === 29) && <small>{new Date(`${point.date}T12:00:00`).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}</small>}</div>)}</div></div></article>
      <article className="data-panel category-panel"><div className="panel-heading"><div><small className="panel-kicker">SIGNAL BREAKDOWN</small><h3>Threat categories</h3></div><Sparkles size={17}/></div>{data.threat_categories.length ? <div className="category-list">{data.threat_categories.slice(0, 5).map(item => <div key={item.label}><span>{titleCase(item.label)}</span><b>{item.count}</b></div>)}</div> : <p className="empty-state">No additional signals in your reports yet.</p>}</article>
      <article className="data-panel attention-panel"><div className="panel-heading"><div><small className="panel-kicker">PRIORITY REVIEW</small><h3>Needs attention</h3></div><ShieldAlert size={17}/></div>{attentionScans.length ? <div className="attention-list">{attentionScans.map(scan => <div className="attention-row" key={scan.scan_id}><span className={`attention-marker ${(scan.risk_level || '').toLowerCase()}`}/><div><strong>{scan.domain}</strong><small>{scan.risk_level} risk · {scan.risk_score ?? '—'}/100</small></div><button className="text-button" onClick={() => onViewScan(scan.scan_id)} aria-label={`View report for ${scan.domain}`}><ArrowRight size={15}/></button></div>)}</div> : <div className="clear-state"><span><ShieldCheck size={17}/></span><p>No high or critical scans in your recent reports.</p></div>}</article>
    </div>
    <article className="data-panel recent-panel"><div className="panel-heading"><div><small className="panel-kicker">LATEST ACTIVITY</small><h3>Recent scans</h3></div><button className="text-button" onClick={onOpenHistory}>Full history <ArrowRight size={14}/></button></div>{data.recent_scans.length ? <div className="table-wrap"><table><thead><tr><th>Domain</th><th>Risk</th><th>Score</th><th>Date</th><th/></tr></thead><tbody>{data.recent_scans.map(scan => <tr key={scan.scan_id}><td>{scan.domain}</td><td><span className={`risk-level ${(scan.risk_level || 'unknown').toLowerCase()}`}>{scan.risk_level || '—'}</span></td><td>{scan.risk_score ?? '—'}</td><td>{metricDate(scan.created_at)}</td><td><button className="text-button" onClick={() => onViewScan(scan.scan_id)}>View</button></td></tr>)}</tbody></table></div> : <p className="empty-state">Your completed scans will appear here.</p>}</article>
  </section>;
}

export function HistoryPage({ rows, busy, error, onSearch, onViewScan }: {
  rows: RecentScan[]; busy: boolean; error: string;
  onSearch: (filters: HistoryFilters) => void; onViewScan: (id: string) => void;
}) {
  const [filters, setFilters] = useState<HistoryFilters>({ risk_level: '', domain: '', brand: '', date_from: '', date_to: '' });
  function submit(event: FormEvent) { event.preventDefault(); onSearch(filters); }
  return <section className="workspace history-page"><div className="page-heading"><small>INVESTIGATIONS</small><h2>Scan history</h2><p>Search saved reports by risk, domain, brand, or date.</p></div>
    <form className="filter-bar" onSubmit={submit}><label>Risk<select value={filters.risk_level} onChange={e => setFilters({ ...filters, risk_level: e.target.value })}><option value="">All levels</option><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select></label><label>Domain<input value={filters.domain} onChange={e => setFilters({ ...filters, domain: e.target.value })} placeholder="Search domain" /></label><label>Brand<input value={filters.brand} onChange={e => setFilters({ ...filters, brand: e.target.value })} placeholder="Search brand" /></label><label>From<input type="date" value={filters.date_from} onChange={e => setFilters({ ...filters, date_from: e.target.value })} /></label><label>To<input type="date" value={filters.date_to} onChange={e => setFilters({ ...filters, date_to: e.target.value })} /></label><button className="primary-button"><Search size={14}/> Apply filters</button></form>
    {error && <p className="error" role="alert">{error}</p>}{busy ? <p className="page-state">Loading scan history…</p> : rows.length ? <div className="data-panel table-wrap"><table><thead><tr><th>URL</th><th>Domain</th><th>Risk</th><th>Score</th><th>Date</th><th>Status</th><th>Action</th></tr></thead><tbody>{rows.map(scan => <tr key={scan.scan_id}><td className="url-cell">{scan.normalized_url || scan.domain}</td><td>{scan.domain}</td><td><span className={`risk-level ${(scan.risk_level || 'unknown').toLowerCase()}`}>{scan.risk_level || '—'}</span></td><td>{scan.risk_score ?? '—'}</td><td>{metricDate(scan.created_at)}</td><td>{scan.status}</td><td><button className="text-button" onClick={() => onViewScan(scan.scan_id)}>View report</button></td></tr>)}</tbody></table></div> : <div className="data-panel empty-state"><ShieldAlert size={20}/><p>No scans match these filters.</p></div>}
  </section>;
}
