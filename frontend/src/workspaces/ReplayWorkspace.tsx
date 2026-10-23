import React, { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, Copy, GitCompare, Loader2, Plus, Send, Sparkles, X } from 'lucide-react';
import { ReplayFailure, TransactionRecord } from '../types';
import { bytesToText, formatBytes, formatDuration, statusClass } from '../lib/http';
import { AnalyzeModal } from '../components/AnalyzeModal';
import { blockingIssues, destinationOf, NEW_DRAFT, parseHeaderLines, REPLAY_METHODS, ReplayDraft, STATE_CHANGING } from '../lib/replay';
import { Attempt, MAX_ATTEMPTS, MAX_TABS, ReplaySessions, ReplayTab, TAB_COLORS } from '../lib/replaySessions';
import { useStoredState } from '../lib/useStoredState';
import { engine } from '../lib/transport';
import { MessagePane, Side } from '../components/MessagePane';
import { ReplayCompare } from '../components/ReplayCompare';
import { Splitter } from '../components/Splitter';

interface ReplayWorkspaceProps {
  active: boolean;
  sessions: ReplaySessions;
  onToast: (msg: string) => void;
}

const MIN_PANE = 280;

const FAILURE_TITLE: Record<string, string> = {
  refused: 'Connection refused',
  timeout: 'Timed out',
  resolve: 'Host not found',
  connect: "Couldn't connect",
  malformed: 'Malformed response',
  interrupted: 'Response incomplete',
  unsupported: 'Not supported',
  loop: 'Not sent: DropSuite listener',
  blocked: 'Not sent: restricted address',
  invalid: 'Not sent',
  cancelled: 'Cancelled',
  busy: 'Already sending',
};

const CHALLENGE_VENDOR: Record<string, string> = {
  cloudflare: 'Cloudflare',
  akamai: 'Akamai',
  data_dome: 'DataDome',
  imperva: 'Imperva',
  sucuri: 'Sucuri',
};

const CHALLENGE_KIND: Record<string, string> = {
  js: 'JavaScript challenge',
  interactive: 'interactive challenge',
  blocked: 'blocked',
  rate_limited: 'rate limit',
};

const CHALLENGE_HINT: Record<string, string> = {
  js: 'A browser must run the check. Press Open browser, finish it there, then Import cookies.',
  interactive: 'Press Open browser, finish it there, then Import cookies.',
  blocked: 'Try a browser preset; if it persists the address or session is refused.',
  rate_limited: 'Wait and retry, or lower Fuzzer concurrency.',
};

const clock = (t: number) => new Date(t).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });

export const ReplayWorkspace: React.FC<ReplayWorkspaceProps> = ({ active, sessions, onToast }) => {
  const tab = sessions.tabs.find((t) => t.id === sessions.activeId) ?? sessions.tabs[0];
  const [compare, setCompare] = useState(false);
  const [picks, setPicks] = useState<Record<number, { a?: number; b?: number }>>({});
  const [renaming, setRenaming] = useState<number | null>(null);
  const [colorMenuId, setColorMenuId] = useState<number | null>(null);
  const [ratio, setRatio] = useStoredState<number>('replay.ratio', 0.5);
  const bodyRef = useRef<HTMLDivElement>(null);
  const urlRef = useRef<HTMLInputElement>(null);
  const [width, setWidth] = useState(1200);

  useLayoutEffect(() => {
    const el = bodyRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setWidth(el.clientWidth));
    ro.observe(el);
    setWidth(el.clientWidth);
    return () => ro.disconnect();
  }, [compare]);

  const draft = tab.draft;
  const parsed = useMemo(() => parseHeaderLines(draft.headersText), [draft.headersText]);
  const issues = useMemo(() => blockingIssues(draft, parsed), [draft, parsed]);
  const dest = destinationOf(draft.url);
  const inflight = sessions.inflight;
  const sendingHere = inflight?.tabId === tab.id;
  const busyElsewhere = !!inflight && !sendingHere;
  const canSend = issues.length === 0 && !inflight;
  const set = (patch: Partial<ReplayDraft>) => sessions.setDraft(tab.id, { ...draft, ...patch });

  const completed = tab.attempts.filter((a) => a.response);
  const pick = picks[tab.id] ?? {};
  const pickA = completed.find((a) => a.seq === pick.a) ?? completed[completed.length - 2];
  const pickB = completed.find((a) => a.seq === pick.b) ?? completed[completed.length - 1];
  const setPick = (side: 'a' | 'b', seq: number) => setPicks((p) => ({ ...p, [tab.id]: { a: pickA?.seq, b: pickB?.seq, ...p[tab.id], [side]: seq } }));

  const sendNow = () => {
    if (!canSend || !dest) return;
    sessions.send(tab.id, { method: draft.method, url: draft.url.trim(), headers: parsed.headers, body: draft.body }, dest.label);
  };
  const newTab = () => {
    if (!sessions.open({ ...NEW_DRAFT })) onToast(`Close a Replay tab first (at most ${MAX_TABS} are open).`);
    else requestAnimationFrame(() => urlRef.current?.focus());
  };
  const duplicateTab = () => {
    if (!sessions.duplicate(tab.id)) onToast(`Close a Replay tab first (at most ${MAX_TABS} are open).`);
    else onToast('Tab duplicated. Nothing has been sent.');
  };
  const closeTab = (t: ReplayTab) => {
    if (inflight?.tabId === t.id) {
      onToast('This tab is sending. Cancel or wait before closing it.');
      return;
    }
    sessions.close(t.id);
  };

  useEffect(() => {
    if (!active) return;
    const onKey = (e: KeyboardEvent) => {
      const ctrl = e.ctrlKey || e.metaKey;
      const tabs = sessions.tabs;
      const i = tabs.findIndex((t) => t.id === tab.id);
      if (ctrl && e.key === 'Enter') sendNow();
      else if (ctrl && !e.shiftKey && e.key.toLowerCase() === 't') newTab();
      else if (ctrl && !e.shiftKey && e.key.toLowerCase() === 'w') closeTab(tab);
      else if (ctrl && !e.shiftKey && e.key.toLowerCase() === 'd') duplicateTab();
      else if (ctrl && e.key === 'Tab') sessions.setActiveId(tabs[(i + (e.shiftKey ? tabs.length - 1 : 1)) % tabs.length].id);
      else if (e.key === 'F2') setRenaming(tab.id);
      // Esc leaves Compare from anywhere except the editors, where it is just a key.
      else if (e.key === 'Escape' && compare && !(e.target instanceof HTMLTextAreaElement)) setCompare(false);
      else return;
      e.preventDefault();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  const reqPx = Math.min(width - MIN_PANE, Math.max(MIN_PANE, width * ratio));
  const changing = STATE_CHANGING.includes(draft.method);
  const inflightTab = inflight ? sessions.tabs.find((t) => t.id === inflight.tabId) : undefined;

  return (
    <div className="workspace replay" style={{ display: active ? 'flex' : 'none', flex: 1 }}>
      <div className="replay-tabs" role="tablist" aria-label="Replay tabs">
        {sessions.tabs.map((t) => {
          const colorObj = TAB_COLORS.find((c) => c.id === t.color);
          return (
            <div
              key={t.id}
              className="replay-tab"
              role="presentation"
              aria-current={t.id === tab.id ? 'true' : undefined}
              style={{ position: 'relative' }}
            >
              <button
                type="button"
                className="replay-color-dot"
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  background: colorObj ? colorObj.hex : 'var(--text-3)',
                  border: 'none',
                  cursor: 'pointer',
                  padding: 0,
                  margin: '0 4px 0 6px',
                  opacity: colorObj ? 1 : 0.35,
                  flexShrink: 0,
                }}
                title={`Tab color: ${colorObj?.label ?? 'Default'} (click to change)`}
                onClick={(e) => {
                  e.stopPropagation();
                  setColorMenuId((cur) => (cur === t.id ? null : t.id));
                }}
              />
              {colorMenuId === t.id && (
                <div
                  style={{
                    position: 'absolute',
                    top: '100%',
                    left: 4,
                    zIndex: 100,
                    background: 'var(--panel)',
                    border: '1px solid var(--line-strong)',
                    borderRadius: 6,
                    padding: 6,
                    display: 'flex',
                    gap: 6,
                    boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
                  }}
                  onClick={(e) => e.stopPropagation()}
                >
                  {TAB_COLORS.map((c) => (
                    <button
                      key={c.id}
                      type="button"
                      style={{
                        width: 16,
                        height: 16,
                        borderRadius: '50%',
                        background: c.hex,
                        border: (t.color ?? 'gray') === c.id ? '2px solid white' : '1px solid transparent',
                        cursor: 'pointer',
                        padding: 0,
                      }}
                      title={c.label}
                      onClick={() => {
                        sessions.setColor(t.id, c.id === 'gray' ? null : c.id);
                        setColorMenuId(null);
                      }}
                    />
                  ))}
                </div>
              )}
              {renaming === t.id ? (
                <input
                  className="text-input replay-rename"
                  aria-label="Tab name"
                  autoFocus
                  defaultValue={t.name}
                  maxLength={40}
                  onFocus={(e) => e.currentTarget.select()}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      sessions.rename(t.id, e.currentTarget.value);
                      setRenaming(null);
                    } else if (e.key === 'Escape') setRenaming(null);
                    e.stopPropagation();
                  }}
                  onBlur={(e) => {
                    sessions.rename(t.id, e.currentTarget.value);
                    setRenaming(null);
                  }}
                />
              ) : (
                <button
                  role="tab"
                  aria-selected={t.id === tab.id}
                  className="replay-tab-name"
                  title={`${t.name} (double-click or F2 to rename)`}
                  onClick={() => sessions.setActiveId(t.id)}
                  onDoubleClick={() => setRenaming(t.id)}
                >
                  {inflight?.tabId === t.id && <Loader2 size={11} className="spin" />}
                  {t.groupName && (
                    <span style={{ fontSize: 10, opacity: 0.6, marginRight: 4, textTransform: 'uppercase' }}>
                      [{t.groupName}]
                    </span>
                  )}
                  {t.name}
                </button>
              )}
              <button
                className="replay-tab-close"
                aria-label={`Close ${t.name}`}
                title="Close tab (Ctrl+W)"
                onClick={() => closeTab(t)}
              >
                <X size={11} />
              </button>
            </div>
          );
        })}
        <button className="icon-btn replay-tab-new" aria-label="New Replay tab" title="New tab (Ctrl+T)" disabled={sessions.tabs.length >= MAX_TABS} onClick={newTab}>
          <Plus size={13} />
        </button>
        <span className="replay-tabs-count">
          {sessions.tabs.length}/{MAX_TABS}
        </span>
      </div>

      <div className="toolbar" role="toolbar" aria-label="Replay request">
        <select className="select replay-method" aria-label="Method" value={draft.method} onChange={(e) => set({ method: e.target.value })}>
          {REPLAY_METHODS.map((m) => (
            <option key={m}>{m}</option>
          ))}
        </select>
        <input
          ref={urlRef}
          className="text-input mono replay-url"
          aria-label="Target URL"
          placeholder="http://host:port/path"
          spellCheck={false}
          value={draft.url}
          onChange={(e) => set({ url: e.target.value })}
        />
        {sendingHere ? (
          <button className="btn" onClick={() => sessions.cancel()}>
            <X size={12} /> Cancel
          </button>
        ) : (
          <button
            className="btn btn-primary replay-send"
            disabled={!canSend}
            onClick={sendNow}
            title={
              busyElsewhere
                ? 'Another Replay request is running'
                : canSend
                  ? 'Send (Ctrl+Enter)'
                  : issues[0]
                    ? `Can't send: ${issues[0].text}${compare ? ' — open Editor to fix it.' : ''}`
                    : 'Resolve the issues below the request first'
            }
          >
            <Send size={12} /> Send
          </button>
        )}
        <button className="btn" onClick={duplicateTab} disabled={sessions.tabs.length >= MAX_TABS} title="Duplicate this tab without sending (Ctrl+D)">
          <Copy size={12} /> Duplicate
        </button>
        <button
          className="btn replay-compare-toggle"
          aria-pressed={compare}
          disabled={!compare && completed.length < 2}
          onClick={() => setCompare((c) => !c)}
          title={completed.length < 2 ? 'Send at least twice to compare responses' : compare ? 'Back to the editor (Esc)' : 'Compare two responses'}
        >
          <GitCompare size={12} /> {compare ? 'Editor' : 'Compare'}
        </button>
      </div>

      <div className="replay-meta" aria-live="polite">
        <span>
          Destination <strong className="mono">{dest ? dest.label : '-'}</strong>
        </span>
        {busyElsewhere ? (
          <span className="replay-warn">
            <Loader2 size={11} className="spin" /> Another request is running in “{inflightTab?.name}”. Wait for it or cancel it there.
          </span>
        ) : (
          <span>Sent only when you press Send · direct to the target · never saved</span>
        )}
        {changing && !busyElsewhere && (
          <span className="replay-warn">
            <AlertTriangle size={11} /> {draft.method} can change data on the server
          </span>
        )}
      </div>

      {compare ? (
        <div className="replay-body compare-mode" ref={bodyRef}>
          <div className="compare-picker">
            <div className="attempts-head">Pick two responses</div>
            <AttemptList attempts={tab.attempts} pickA={pickA?.seq} pickB={pickB?.seq} onPick={setPick} />
          </div>
          <div className="compare-main">
            {pickA && pickB && pickA.seq !== pickB.seq ? (
              <ReplayCompare a={pickA} b={pickB} />
            ) : (
              <div className="state">
                <h2>Pick two different responses</h2>
                <p>Choose A and B in the list. Only completed responses can be compared.</p>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="insp-body replay-body" ref={bodyRef}>
          <div className="pane" style={{ width: reqPx, flexShrink: 0 }}>
            <section className="msg req-editor" aria-label="Request editor">
              <div className="msg-head">
                <span className="msg-title">Request</span>
                <span className="editor-badge">Editable</span>
              </div>
              <label className="editor-label" htmlFor="replay-headers">
                Headers <span>one per line, Name: value · Host and Content-Length are set on send</span>
              </label>
              <textarea id="replay-headers" className="code-input headers" spellCheck={false} wrap="off" value={draft.headersText} onChange={(e) => set({ headersText: e.target.value })} />
              <label className="editor-label" htmlFor="replay-body">
                Body <span>{formatBytes(new TextEncoder().encode(draft.body).length)} · UTF-8</span>
              </label>
              <textarea
                id="replay-body"
                className="code-input body"
                spellCheck={false}
                value={draft.body}
                placeholder={draft.source?.omittedBody ? 'The original body was not stored. Write a new body here.' : 'No body'}
                onChange={(e) => set({ body: e.target.value })}
              />
              {(issues.length > 0 || (draft.source?.notCopied.length ?? 0) > 0) && (
                <div className="replay-issues">
                  {issues.length > 0 && (
                    <ul role="alert" aria-label="Before sending">
                      {issues.map((i) => (
                        <li key={i.text}>
                          {i.text}
                          {i.ackBody && (
                            <button className="link-btn" onClick={() => set({ bodyAcknowledged: true })}>
                              Send without a body
                            </button>
                          )}
                        </li>
                      ))}
                    </ul>
                  )}
                  {draft.source && draft.source.notCopied.length > 0 && <p className="note">Not copied from history: {draft.source.notCopied.join(', ')}.</p>}
                </div>
              )}
            </section>
          </div>
          <Splitter orientation="vertical" label="Resize request and response" value={reqPx} min={MIN_PANE} max={width - MIN_PANE} onChange={(px) => setRatio(px / width)} onReset={() => setRatio(0.5)} />
          <div className="pane replay-response-col" style={{ flex: 1 }}>
            {tab.attempts.length > 0 && (
              <>
                <div className="attempts-head">
                  Sent {tab.attempts.length === 1 ? 'once' : `${tab.attempts.length} times`}
                  <span>
                    last {Math.min(tab.attempts.length, MAX_ATTEMPTS)} of at most {MAX_ATTEMPTS} kept in memory
                  </span>
                </div>
                <AttemptList attempts={tab.attempts} selected={tab.viewSeq ?? tab.attempts[tab.attempts.length - 1].seq} onSelect={(seq) => sessions.view(tab.id, seq === tab.attempts[tab.attempts.length - 1].seq ? null : seq)} />
              </>
            )}
            <ResponsePanel tab={tab} sending={sendingHere ? inflight?.destination : undefined} onLatest={() => sessions.view(tab.id, null)} onToast={onToast} />
          </div>
        </div>
      )}
    </div>
  );
};

/** Compact list of this tab's sends. Selecting one shows its snapshot; nothing is resent. */
const AttemptList: React.FC<{
  attempts: Attempt[];
  selected?: number;
  onSelect?: (seq: number) => void;
  pickA?: number;
  pickB?: number;
  onPick?: (side: 'a' | 'b', seq: number) => void;
}> = ({ attempts, selected, onSelect, pickA, pickB, onPick }) => (
  <ul className="attempts" aria-label="Sent requests">
    {[...attempts].reverse().map((a) => {
      const r = a.response;
      const body = (
        <>
          <span className="seq mono">#{a.seq}</span>
          <span className="time mono">{clock(a.at)}</span>
          <span className="method">{a.method}</span>
          <span className="status-cell">
            {r ? <span className={`status mono ${statusClass(r.status)}`}>{r.status}</span> : <span className="status failed">✕ {FAILURE_TITLE[a.failure?.kind ?? ''] ?? 'Failed'}</span>}
            {r?.challenge && (
              <span className="chal-tag mono" title={r.challenge.evidence}>
                {CHALLENGE_VENDOR[r.challenge.vendor]}
              </span>
            )}
          </span>
          <span className="dur mono">{r ? formatDuration(r.duration_ms) : ''}</span>
          <span className="size mono">{r ? formatBytes(r.total_bytes) : ''}</span>
        </>
      );
      return (
        <li key={a.seq} className={`attempt${r ? '' : ' is-failed'}`}>
          {onPick ? (
            <>
              <span className="attempt-row">{body}</span>
              <span className="ab-picks">
                {(['a', 'b'] as const).map((side) => (
                  <button
                    key={side}
                    className={`ab ${side}`}
                    aria-pressed={(side === 'a' ? pickA : pickB) === a.seq}
                    aria-label={`Use #${a.seq} as ${side.toUpperCase()}`}
                    disabled={!r}
                    onClick={() => onPick(side, a.seq)}
                  >
                    {side.toUpperCase()}
                  </button>
                ))}
              </span>
            </>
          ) : (
            <button className="attempt-row" aria-pressed={selected === a.seq} onClick={() => onSelect?.(a.seq)}>
              {body}
            </button>
          )}
        </li>
      );
    })}
  </ul>
);

const ResponsePanel: React.FC<{ tab: ReplayTab; sending?: string; onLatest: () => void; onToast: (m: string) => void }> = ({ tab, sending, onLatest, onToast }) => {
  const [side, setSide] = useState<Side>('response');
  const [analyze, setAnalyze] = useState(false);
  const [jarNames, setJarNames] = useState<string[]>([]);
  const jarShown = tab.attempts.find((a) => a.seq === tab.viewSeq) ?? tab.attempts[tab.attempts.length - 1];
  const jarHost = (jarShown?.response?.destination ?? "").replace(/:\d+$/, "");
  const loadJar = useCallback(async () => {
    if (!jarHost) {
      setJarNames([]);
      return;
    }
    try {
      const rows = await engine.listCookiesForHost(jarHost);
      setJarNames(rows.map((x) => x.name));
    } catch {
      setJarNames([]);
    }
  }, [jarHost]);
  useEffect(() => {
    void loadJar();
  }, [loadJar, jarShown?.response?.cookies_attached]);

  if (sending) {
    return (
      <div className="state" aria-busy="true">
        <h2>
          <Loader2 size={15} className="spin" /> Sending to {sending}
        </h2>
        <p>Waiting up to 20 seconds for the response. Cancel stops waiting; the server may still receive the request.</p>
      </div>
    );
  }
  const latest = tab.attempts[tab.attempts.length - 1];
  const shown = tab.attempts.find((a) => a.seq === tab.viewSeq) ?? latest;
  if (!shown) {
    return (
      <div className="state">
        <h2>No response yet</h2>
        <p>Edit the request, check the destination, then press Send. Nothing is sent until you do.</p>
        <p className="note">Ctrl+Enter sends · Ctrl+T new tab · Ctrl+D duplicate · Ctrl+W close · F2 rename. Redirects are shown, not followed, and nothing is retried.</p>
      </div>
    );
  }
  const old = shown.seq !== latest.seq;
  const banner = old && (
    <div className="snapshot-banner" role="note">
      Snapshot #{shown.seq} from {clock(shown.at)}, a saved response, not the editor's current request.
      <button className="link-btn" onClick={onLatest}>
        Show latest (#{latest.seq})
      </button>
    </div>
  );
  if (!shown.response) {
    const f = shown.failure as ReplayFailure;
    return (
      <>
        {banner}
        <div className="state error" role="alert">
          <h2>
            <AlertTriangle size={16} /> {FAILURE_TITLE[f.kind] ?? 'Not sent'}
          </h2>
          <p>{f.message}</p>
        </div>
      </>
    );
  }
  const r = shown.response;
  const host = r.destination.replace(/:\d+$/, '');

  const solveChallenge = async (importAfter: boolean) => {
    try {
      if (!importAfter) {
        await engine.openChallengeBrowser(`https://${host}/`);
        onToast(`Finish the check in the browser window, then press Import cookies.`);
      } else {
        const out = await engine.importChallengeCookies(host);
        void loadJar();
        const names = out.imported.join(', ');
        onToast(
          out.has_clearance
            ? `cf_clearance imported for ${host} (${names}). Replay again.`
            : `${out.imported.length} cookie(s) from the window: ${names}. No cf_clearance yet - finish the check, then import again.`,
        );
      }
    } catch (e) {
      onToast(e instanceof Error ? e.message : String(e));
    }
  };
  // MessagePane renders captured records; a snapshot is shaped like one (never stored).
  const record: TransactionRecord = {
    id: -shown.seq,
    timestamp: shown.at,
    duration_ms: r.duration_ms,
    method: shown.method,
    url: r.request_target,
    host: r.destination,
    path: r.request_target,
    request_headers: r.request_headers,
    request_body: r.request_message,
    status_code: r.status,
    response_headers: r.headers,
    response_body: r.message,
    content_type: r.content_type ?? undefined,
    content_length: r.total_bytes,
  };
  const switcher = (
    <div className="msg-title switch" role="tablist" aria-label="Snapshot">
      {(['response', 'request'] as Side[]).map((s) => (
        <button key={s} role="tab" aria-selected={side === s} onClick={() => setSide(s)}>
          {s === 'response' ? 'Response' : 'Request sent'}
        </button>
      ))}
    </div>
  );
  return (
    <div className="replay-response">
      {banner}
      {r.challenge && (
        <div className="snapshot-banner" role="status" data-challenge={r.challenge.kind}>
          <strong>{CHALLENGE_VENDOR[r.challenge.vendor]}</strong> {CHALLENGE_KIND[r.challenge.kind]} - the
          request never reached the application. {CHALLENGE_HINT[r.challenge.kind]}
          <span className="field-hint mono" style={{ marginLeft: 6 }}>({r.challenge.evidence})</span>
          <span className="chrome-spacer" />
          <button className="link-btn" onClick={() => void solveChallenge(false)}>
            Open browser
          </button>
          <button className="link-btn" onClick={() => void solveChallenge(true)}>
            Import cookies
          </button>
          <span
            className="field-hint"
            title={jarNames.join(", ")}
            data-jar-count={jarNames.length}
          >
            {jarNames.length > 0
              ? `jar: ${jarNames.length} for this host (${jarNames.slice(0, 3).join(", ")}${jarNames.length > 3 ? "…" : ""})`
              : "jar: empty for this host"}
            {jarNames.length > 0 && !jarNames.some((n) => n.toLowerCase() === "cf_clearance")
              ? " - no cf_clearance yet"
              : ""}
          </span>
        </div>
      )}
      <div className="insp-head">
        <span className={`status mono ${statusClass(r.status)}`}>{r.status}</span>
        <span className="target">
          <span className="path">{r.reason || '-'}</span>
          <span className="host">{r.destination}</span>
        </span>
        <span className="insp-facts">
          <span>#{shown.seq}</span>
          <span>{formatDuration(r.duration_ms)}</span>
          <span title="Cookies attached from the jar for this host">jar: {r.cookies_attached}</span>
          <span title="Response bytes received, head included">{formatBytes(r.total_bytes)} received</span>
          <span title="Request bytes sent, head included">{formatBytes(r.sent_bytes)} sent</span>
          <span>Not saved</span>
        </span>
        <button className="fz-pill fz-ai insp-analyze" onClick={() => setAnalyze(true)} title="Ask Drop AI to review this request and response">
          <Sparkles size={12} /> Analyze with AI
        </button>
      </div>
      {analyze && (
        <AnalyzeModal
          requestText={bytesToText(new Uint8Array(r.request_message))}
          responseText={bytesToText(new Uint8Array(r.message))}
          contentType={r.content_type ?? undefined}
          onClose={() => setAnalyze(false)}
          onToast={onToast}
        />
      )}
      {r.dropped_headers.length > 0 && side === 'request' && <div className="content-note">Not sent (connection-only fields): {r.dropped_headers.join(', ')}.</div>}
      <div className="replay-response-body">
        <MessagePane key={`${record.id}-${side}`} side={side} record={record} title={switcher} onCopied={onToast} />
      </div>
    </div>
  );
};
