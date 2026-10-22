import React, { useEffect, useRef, useState } from 'react';
import { Loader2, RefreshCw, Search, Sparkles, Trash2 } from 'lucide-react';
import { engine, intruder } from '../lib/transport';
import { analyzeResponse, Severity } from '../lib/findings';
import { bytesToText, extractParams, formatBytes, parseMessage, statusClass } from '../lib/http';
import { ReplayDraft } from '../lib/replay';
import { AiResultModal } from '../components/AiResultModal';
import { COMMON_PATHS } from '../lib/pathlist';

interface ScannerWorkspaceProps {
  active: boolean;
  onToast: (msg: string) => void;
  onSendToReplay?: (draft: ReplayDraft, label: string) => void;
}

interface Agg {
  severity: Severity;
  title: string;
  detail: string;
  count: number;
  hosts: Set<string>;
  urls: string[];
}

interface DiscRow {
  path: string;
  status: number;
  length: number;
}

type Mode = 'passive' | 'discovery';

const SEV_RANK: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };
const MAX_SCAN = 500;

const TRIAGE_SYSTEM =
  'You are a web security tester triaging aggregated passive scan findings from an AUTHORIZED assessment. For each finding give one compact block: the finding name, a verdict (Likely true positive / Likely false positive / Needs manual check), a priority (High / Medium / Low), and a one-line remediation. No preamble.';
const REPORT_SYSTEM =
  'You are a penetration tester writing a passive scan report for an AUTHORIZED assessment. Output GitHub-flavoured Markdown only: a short summary with counts by severity, then a "## Findings" section with one "### " subsection per finding (Severity, Affected hosts, Description, Impact, Remediation). Ready to paste. No preamble before the Markdown.';

export const ScannerWorkspace: React.FC<ScannerWorkspaceProps> = ({ active, onToast, onSendToReplay }) => {
  const [mode, setMode] = useState<Mode>('passive');

  // --- Passive scan state ---
  const [scanning, setScanning] = useState(false);
  const [rows, setRows] = useState<Agg[]>([]);
  const [scanned, setScanned] = useState(0);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ai, setAi] = useState<{ title: string; system: string; prompt: string } | null>(null);
  const [host, setHost] = useState<string>('all');
  const [hosts, setHosts] = useState<string[]>([]);
  const started = useRef(false);

  // --- Content discovery state ---
  const [baseUrl, setBaseUrl] = useState('https://');
  const [discovering, setDiscovering] = useState(false);
  const [drows, setDrows] = useState<DiscRow[]>([]);
  const [dProgress, setDProgress] = useState({ done: 0, total: 0 });
  const [derror, setDerror] = useState<string | null>(null);
  const [baseline, setBaseline] = useState<{ status: number; length: number } | null>(null);
  const [catchAll, setCatchAll] = useState(false);
  // Why a run produced no rows: probes the engine refused to send (Scope) vs. ones that failed to
  // connect. Without this the table just sits empty and the tester can't tell a clean "nothing here"
  // from "nothing was ever sent".
  const [diag, setDiag] = useState<{ scope: number; failed: number; sampleErr: string | null }>({ scope: 0, failed: 0, sampleErr: null });

  const scan = async (filterHost: string = host) => {
    setScanning(true);
    setError(null);
    setRows([]);
    setScanned(0);
    setDone(false);
    try {
      const summaries = await engine.history('', '');
      // Keep the host picker populated from the full capture, even while a single host is scanned.
      setHosts([...new Set(summaries.map((s) => s.host).filter(Boolean))].sort());
      const list = summaries.slice(0, MAX_SCAN).filter((s) => filterHost === 'all' || s.host === filterHost);
      const map = new Map<string, Agg>();
      let count = 0;
      for (const s of list) {
        try {
          const rec = await engine.transaction(s.id);
          const paramValues = extractParams(rec.url, parseMessage(rec.request_body).body, rec.request_headers).map((p) => p.value);
          const bodyText = bytesToText(parseMessage(rec.response_body).body);
          const findings = analyzeResponse({ url: rec.url, status: rec.status_code, headers: rec.response_headers, body: bodyText, paramValues });
          for (const f of findings) {
            const key = `${f.severity}|${f.title}`;
            let a = map.get(key);
            if (!a) {
              a = { severity: f.severity, title: f.title, detail: f.detail, count: 0, hosts: new Set(), urls: [] };
              map.set(key, a);
            }
            a.count++;
            a.hosts.add(rec.host);
            if (a.urls.length < 25) a.urls.push(`${rec.method} ${rec.url}`);
          }
        } catch {
          /* skip a record that fails to load */
        }
        count++;
        if (count % 20 === 0) setScanned(count);
      }
      setScanned(count);
      const agg = [...map.values()].sort((x, y) => SEV_RANK[x.severity] - SEV_RANK[y.severity] || y.count - x.count);
      // Group affected requests tidily (by method+URL) instead of raw capture order.
      agg.forEach((a) => a.urls.sort());
      setRows(agg);
      setDone(true);
      onToast(agg.length ? `Scan complete: ${agg.length} issue type(s) across ${count} request(s).` : `Scan complete: no passive issues in ${count} request(s).`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setScanning(false);
    }
  };

  useEffect(() => {
    if (active && mode === 'passive' && !started.current) {
      started.current = true;
      scan();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, mode]);

  // Clear the findings on screen. The scanner holds no stored state of its own — it is derived
  // from HTTP history — so this clears the view only, and it stays empty until Rescan. To remove
  // the underlying traffic, use Clear in the Proxy tab. started.current stays true so the auto-scan
  // does not immediately refill the panel.
  const clearFindings = () => {
    setRows([]);
    setScanned(0);
    setDone(false);
    setError(null);
  };

  const discover = async () => {
    const base = baseUrl.trim().replace(/\/+$/, '');
    if (!/^https?:\/\//i.test(base)) {
      setDerror('Base URL must start with http:// or https://');
      return;
    }
    setDiscovering(true);
    setDerror(null);
    setDrows([]);
    setBaseline(null);
    setCatchAll(false);
    setDiag({ scope: 0, failed: 0, sampleErr: null });
    // Calibration: two random paths that should not exist. Their response is the "baseline"; any
    // real path must differ from it. This defeats catch-all/SPA servers that return 200 for
    // everything (soft-404).
    const rand = Math.random().toString(36).slice(2, 10);
    const sentinels = [`zzdrop-${rand}-404`, `${rand}-does-not-exist-zz`];
    const sentinelSet = new Set(sentinels);
    setDProgress({ done: 0, total: sentinels.length + COMMON_PATHS.length });
    try {
      const request = { method: 'GET', url: `${base}/{{}}`, headers: [] as [string, string][], body: '' };
      const attack = { type: 'sniper' as const, payloads: { kind: 'list' as const, values: [...sentinels, ...COMMON_PATHS] } };
      await intruder.start(request, attack, 12, 0, 5000, false);
      let loaded = 0;
      let failed = 0;
      let sampleErr: string | null = null;
      const all: DiscRow[] = [];
      for (;;) {
        const st = await intruder.status();
        const more = await intruder.results(loaded, 1000);
        loaded += more.length;
        for (const r of more) {
          if (r.ok && r.status) {
            all.push({ path: r.replacements.join(''), status: r.status, length: r.total_bytes ?? 0 });
          } else if (r.error_kind !== 'scope') {
            // Scope refusals are counted by the engine (st.scope_skipped); tally only real send failures here.
            failed++;
            if (!sampleErr && r.error_message) sampleErr = r.error_message;
          }
        }
        // Baseline from the sentinels (if they came back).
        const sent = all.filter((a) => sentinelSet.has(a.path));
        const bl = sent.length ? { status: sent[0].status, length: Math.max(...sent.map((s) => s.length)) } : null;
        const tol = bl ? Math.max(512, Math.round(bl.length * 0.02)) : 0;
        const distinct = all
          .filter((a) => !sentinelSet.has(a.path) && a.status !== 404 && (!bl || a.status !== bl.status || Math.abs(a.length - bl.length) > tol))
          .sort((x, y) => x.status - y.status || x.path.localeCompare(y.path));
        setBaseline(bl);
        setCatchAll(!!bl && bl.status >= 200 && bl.status < 400);
        setDrows(distinct);
        setDProgress({ done: st.completed, total: st.planned });
        setDiag({ scope: st.scope_skipped, failed, sampleErr });
        if (st.done && loaded >= st.completed) break;
        await new Promise((res) => setTimeout(res, 350));
      }
      onToast('Discovery done.');
    } catch (e) {
      setDerror(e instanceof Error ? e.message : String(e));
    } finally {
      setDiscovering(false);
    }
  };

  const openDisc = (path: string) => {
    if (!onSendToReplay) return;
    const base = baseUrl.trim().replace(/\/+$/, '');
    onSendToReplay({ method: 'GET', url: `${base}/${path}`, headersText: '', body: '' }, `Discover /${path}`);
  };

  const summaryText = () => {
    const by = (s: Severity) => rows.filter((r) => r.severity === s).length;
    return `${by('high')} high · ${by('medium')} medium · ${by('low')} low · ${by('info')} info`;
  };

  const aiPrompt = () =>
    `Aggregated passive scan findings (authorized assessment):\n\n` +
    rows.map((r) => `- [${r.severity}] ${r.title} (${r.count}x, hosts: ${[...r.hosts].join(', ')}): ${r.detail}`).join('\n');

  // Host of the discovery target, for the Scope hint. '' while the URL is still being typed.
  const discHost = (() => {
    try {
      return new URL(baseUrl.trim()).host;
    } catch {
      return '';
    }
  })();

  return (
    <div className="workspace scanner" style={{ display: active ? 'flex' : 'none', flex: 1, flexDirection: 'column' }}>
      <div className="scanner-modes">
        <button className={`fz-pill${mode === 'passive' ? ' on' : ''}`} onClick={() => setMode('passive')}>
          Passive
        </button>
        <button className={`fz-pill${mode === 'discovery' ? ' on' : ''}`} onClick={() => setMode('discovery')}>
          Content discovery
        </button>
      </div>

      {mode === 'passive' ? (
        <>
          <div className="scanner-head">
            <span className="fz-title">Passive Scanner</span>
            <span className="fz-count">
              {scanning ? (
                <>
                  <Loader2 size={12} className="spin" /> Scanning… {scanned} request(s)
                </>
              ) : done ? (
                `${scanned} requests scanned · ${summaryText()}`
              ) : (
                'Reads captured HTTP history and flags security issues. No requests are sent.'
              )}
            </span>
            <select
              className="text-input mono"
              value={host}
              onChange={(e) => {
                setHost(e.target.value);
                scan(e.target.value);
              }}
              disabled={scanning}
              title="Filter findings by host"
              style={{ marginLeft: 'auto', maxWidth: 240 }}
            >
              <option value="all">All hosts{hosts.length ? ` (${hosts.length})` : ''}</option>
              {hosts.map((h) => (
                <option key={h} value={h}>
                  {h}
                </option>
              ))}
            </select>
            <button className="btn" onClick={() => scan()} disabled={scanning}>
              <RefreshCw size={12} /> Rescan
            </button>
            <button className="btn" onClick={clearFindings} disabled={scanning || (rows.length === 0 && !done)} title="Clear the findings shown here (does not delete HTTP history; Rescan rebuilds them)">
              <Trash2 size={12} /> Clear
            </button>
            {rows.length > 0 && (
              <>
                <button className="fz-pill fz-ai" onClick={() => setAi({ title: 'Triage findings (Drop AI)', system: TRIAGE_SYSTEM, prompt: aiPrompt() })} disabled={scanning}>
                  <Sparkles size={11} /> Triage with AI
                </button>
                <button className="fz-pill fz-ai" onClick={() => setAi({ title: 'Draft report (Drop AI)', system: REPORT_SYSTEM, prompt: aiPrompt() })} disabled={scanning}>
                  <Sparkles size={11} /> Draft report
                </button>
              </>
            )}
          </div>
          {error && <p className="fz-issue" style={{ padding: '0 10px' }}>{error}</p>}
          <div className="scanner-body">
            {rows.length === 0 && !scanning ? (
              <div className="body-empty">
                {done ? 'No passive issues found in the captured traffic. Browse the target through the proxy, then Rescan.' : 'Nothing scanned yet. Start the listener, browse your target through the proxy, then open this tab.'}
              </div>
            ) : (
              <ul className="findings">
                {rows.map((r, i) => (
                  <li key={i} className="finding scanner-finding">
                    <span className={`sev-badge sev-${r.severity}`}>{r.severity}</span>
                    <div className="finding-text">
                      <strong>
                        {r.title} <span className="fz-count">×{r.count} · {r.hosts.size} host{r.hosts.size === 1 ? '' : 's'}</span>
                      </strong>
                      <span>{r.detail}</span>
                      <details className="scanner-urls">
                        <summary>Affected requests ({r.urls.length}{r.count > r.urls.length ? '+' : ''})</summary>
                        {r.urls.map((u, j) => (
                          <div key={j} className="scanner-url">{u}</div>
                        ))}
                      </details>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </>
      ) : (
        <>
          <div className="scanner-head">
            <span className="fz-title">Content discovery</span>
            <input
              className="text-input mono"
              style={{ flex: 1, minWidth: 0 }}
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              disabled={discovering}
              placeholder="https://target.site"
              spellCheck={false}
            />
            <button className="btn btn-primary" onClick={discover} disabled={discovering}>
              {discovering ? <Loader2 size={12} className="spin" /> : <Search size={12} />} {discovering ? `Probing ${dProgress.done}/${dProgress.total}` : 'Discover'}
            </button>
          </div>
          <p className="fz-hint" style={{ padding: '0 10px' }}>
            Sends GET for {COMMON_PATHS.length} common paths (e.g. /.env, /admin, /.git/config) plus 2 random paths to calibrate. Only paths whose response <strong>differs from the random baseline</strong> are shown, so catch-all / SPA servers don't flood false positives. Active: it sends requests, so only use it on targets you may test.
          </p>
          {baseline && (
            <p className="fz-hint" style={{ padding: '0 10px' }}>
              Baseline (random path): <strong>{baseline.status}</strong>, {formatBytes(baseline.length)}.
              {catchAll
                ? ' This site answers every path the same way (catch-all / SPA) — identical responses are hidden as false positives. A row below is real only if it truly differs.'
                : ' Real 404s detected, so the paths below actually exist.'}
            </p>
          )}
          {(diag.scope > 0 || diag.failed > 0) && (
            <p className="fz-issue" style={{ padding: '0 10px' }}>
              {diag.scope > 0 && (
                <>
                  <strong>{diag.scope} probe{diag.scope === 1 ? '' : 's'} blocked by your Scope rules</strong> — never sent{discHost ? `, because ${discHost} is out of scope` : ''}. Fix it in <strong>Target → Scope</strong>: add an Include rule for {discHost || 'this host'} (or turn Scope off), then Discover again.
                </>
              )}
              {diag.scope > 0 && diag.failed > 0 && <br />}
              {diag.failed > 0 && (
                <>
                  <strong>{diag.failed} probe{diag.failed === 1 ? '' : 's'} failed to connect</strong>
                  {diag.sampleErr ? ` (${diag.sampleErr})` : ''}. Check {discHost || 'the host'} is reachable from this machine and the scheme (http/https) is right.
                </>
              )}
            </p>
          )}
          {derror && <p className="fz-issue" style={{ padding: '0 10px' }}>{derror}</p>}
          <div className="scanner-body">
            {drows.length === 0 && !discovering ? (
              <div className="body-empty">
                {baseline
                  ? catchAll
                    ? 'Every path returns the same response (catch-all / SPA). No distinct paths found — these are NOT exposed files, just the app shell.'
                    : 'No common paths exist here (all 404 or identical to baseline).'
                  : diag.scope > 0 || diag.failed > 0
                    ? 'No responses to analyze — see the note above.'
                    : 'No paths yet. Enter a base URL and click Discover.'}
              </div>
            ) : (
              <table className="fz-table">
                <thead>
                  <tr>
                    <th>Path</th>
                    <th>Status</th>
                    <th>Length</th>
                  </tr>
                </thead>
                <tbody>
                  {drows.map((r, i) => (
                    <tr key={i} className={onSendToReplay ? 'fz-row-click' : undefined} onClick={() => openDisc(r.path)} title={onSendToReplay ? 'Open in Replay' : undefined}>
                      <td className="fz-payload">/{r.path}</td>
                      <td>
                        <span className={`status ${statusClass(r.status)}`}>{r.status}</span>
                      </td>
                      <td className="fz-num">{formatBytes(r.length)}</td>
                    </tr>
                  ))}
                  {drows.length === 0 && discovering && (
                    <tr>
                      <td colSpan={3} className="fz-empty">Probing… non-404 paths will appear here.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}

      {ai && <AiResultModal title={ai.title} system={ai.system} prompt={ai.prompt} onClose={() => setAi(null)} onToast={onToast} />}
    </div>
  );
};
