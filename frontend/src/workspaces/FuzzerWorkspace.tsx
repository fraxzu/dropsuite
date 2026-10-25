import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Loader2, Play, Plus, Sparkles, Square, X } from 'lucide-react';
import { AttemptRow, IntruderAttack, IntruderStatus, PayloadSet } from '../types';
import { formatBytes, formatDuration, statusClass } from '../lib/http';
import { parseHeaderLines, REPLAY_METHODS, ReplayDraft } from '../lib/replay';
import { dropAi, intruder } from '../lib/transport';
import { redactSecrets } from '../lib/redact';
import { PAYLOAD_LISTS } from '../lib/payloadLists';

interface FuzzerWorkspaceProps {
  active: boolean;
  onToast: (msg: string) => void;
  onSendToReplay: (draft: ReplayDraft, label: string) => void;
}

/** Replace each `{{ }}` marker in order with the next replacement value. */
function renderMarkers(text: string, repl: string[], counter: { i: number }): string {
  return text.replace(/\{\{[\s\S]*?\}\}/g, () => repl[counter.i++] ?? '');
}

type AttackType = 'sniper' | 'cluster_bomb';
type PayloadKind = 'list' | 'number_range';

interface PayloadDraft {
  kind: PayloadKind;
  list: string;
  from: number;
  to: number;
  step: number;
}

const NEW_PAYLOAD: PayloadDraft = { kind: 'list', list: 'admin\nroot\ntest', from: 1, to: 100, step: 1 };

/** Count DropSuite's own `{{ }}` position markers (not Burp's §). */
const MARKER = /\{\{[\s\S]*?\}\}/g;
const countMarkers = (s: string): number => (s.match(MARKER) ?? []).length;

const payloadCount = (d: PayloadDraft): number => {
  if (d.kind === 'list') return d.list.split('\n').filter((l) => l.length > 0).length;
  if (d.step === 0) return 0;
  const span = d.step > 0 ? d.to - d.from : d.from - d.to;
  return span < 0 ? 0 : Math.floor(span / Math.abs(d.step)) + 1;
};

const toPayloadSet = (d: PayloadDraft): PayloadSet =>
  d.kind === 'list'
    ? { kind: 'list', values: d.list.split('\n').filter((l) => l.length > 0) }
    : { kind: 'number_range', from: d.from, to: d.to, step: d.step };

export const FuzzerWorkspace: React.FC<FuzzerWorkspaceProps> = ({ active, onToast, onSendToReplay }) => {
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('https://example.com/user?name={{admin}}');
  const [headersText, setHeadersText] = useState('');
  const [body, setBody] = useState('');

  const [attackType, setAttackType] = useState<AttackType>('sniper');
  const [concurrency, setConcurrency] = useState(8);
  const [delayMs, setDelayMs] = useState(0);
  const [maxAttempts, setMaxAttempts] = useState(1000);
  const [encodeUrl, setEncodeUrl] = useState(true);

  const [payload, setPayload] = useState<PayloadDraft>({ ...NEW_PAYLOAD });
  const [payloadSets, setPayloadSets] = useState<PayloadDraft[]>([{ ...NEW_PAYLOAD }]);

  const [running, setRunning] = useState(false);
  const [status, setStatus] = useState<IntruderStatus | null>(null);
  const [rows, setRows] = useState<AttemptRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [runId, setRunId] = useState(0);
  const loadedRef = useRef(0);
  const [suggestFor, setSuggestFor] = useState<{ apply: (list: string) => void } | null>(null);

  const urlRef = useRef<HTMLInputElement>(null);
  const headersRef = useRef<HTMLTextAreaElement>(null);
  const bodyRef = useRef<HTMLTextAreaElement>(null);
  const focusedRef = useRef<'url' | 'headers' | 'body'>('url');

  const parsed = useMemo(() => parseHeaderLines(headersText), [headersText]);
  const positions = useMemo(
    () => countMarkers(url) + parsed.headers.reduce((n, [, v]) => n + countMarkers(v), 0) + countMarkers(body),
    [url, parsed.headers, body],
  );

  // Cluster bomb needs exactly one payload set per position; keep the array sized to match.
  useEffect(() => {
    if (attackType !== 'cluster_bomb') return;
    setPayloadSets((prev) => {
      if (prev.length === positions) return prev;
      const next = prev.slice(0, positions);
      while (next.length < positions) next.push({ ...NEW_PAYLOAD });
      return next.length ? next : [{ ...NEW_PAYLOAD }];
    });
  }, [attackType, positions]);

  const requestText = useMemo(() => {
    const lines = [`${method} ${url}`];
    for (const [k, v] of parsed.headers) lines.push(`${k}: ${v}`);
    if (body.trim()) lines.push('', body);
    return lines.join('\n');
  }, [method, url, parsed.headers, body]);

  const planned = useMemo(() => {
    if (positions === 0) return 0;
    if (attackType === 'sniper') return positions * payloadCount(payload);
    return payloadSets.reduce((acc, p) => acc * payloadCount(p), 1);
  }, [attackType, positions, payload, payloadSets]);

  const issues = useMemo(() => {
    const out: string[] = [];
    if (!REPLAY_METHODS.includes(method)) out.push(`Method must be one of ${REPLAY_METHODS.join(', ')}.`);
    if (!/^https?:\/\//i.test(url.trim())) out.push('The URL must start with http:// or https://.');
    if (positions === 0) out.push('Mark at least one position with the Add position button.');
    if (attackType === 'sniper' && payloadCount(payload) === 0) out.push('Add at least one payload.');
    if (attackType === 'cluster_bomb') {
      if (payloadSets.length !== positions) out.push('Cluster bomb needs one payload set per position.');
      if (payloadSets.some((p) => payloadCount(p) === 0)) out.push('Every payload set needs at least one payload.');
    }
    if (planned > maxAttempts) out.push(`Plan is ${planned} requests, over the ${maxAttempts} cap. Narrow the payloads or raise the cap.`);
    return out;
  }, [method, url, positions, attackType, payload, payloadSets, planned, maxAttempts]);

  const canStart = issues.length === 0 && !running;

  /** Wrap the current selection in the last-focused editor with `{{ }}`. */
  const addPosition = () => {
    const which = focusedRef.current;
    const el = which === 'url' ? urlRef.current : which === 'headers' ? headersRef.current : bodyRef.current;
    if (!el) return;
    const s = el.selectionStart ?? el.value.length;
    const e = el.selectionEnd ?? s;
    const v = el.value;
    const inner = v.slice(s, e);
    const next = `${v.slice(0, s)}{{${inner}}}${v.slice(e)}`;
    if (which === 'url') setUrl(next);
    else if (which === 'headers') setHeadersText(next);
    else setBody(next);
    requestAnimationFrame(() => {
      el.focus();
      el.setSelectionRange(s + 2, s + 2 + inner.length);
    });
  };

  const start = async () => {
    if (!canStart) return;
    const request = { method, url: url.trim(), headers: parsed.headers, body };
    const attack: IntruderAttack =
      attackType === 'sniper'
        ? { type: 'sniper', payloads: toPayloadSet(payload) }
        : { type: 'cluster_bomb', payload_sets: payloadSets.map(toPayloadSet) };
    try {
      setError(null);
      setRows([]);
      setStatus(null);
      loadedRef.current = 0;
      const count = await intruder.start(request, attack, concurrency, delayMs, maxAttempts, encodeUrl);
      setRunning(true);
      setRunId((x) => x + 1);
      onToast(`Fuzzer started: ${count} request${count === 1 ? '' : 's'} queued.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const cancel = async () => {
    try {
      await intruder.cancel();
      onToast('Stopping the attack. In-flight requests will finish.');
    } catch {
      /* ignore */
    }
  };

  // Poll status + stream results while a run is active.
  useEffect(() => {
    if (!running) return;
    let stopped = false;
    const tick = async () => {
      try {
        const st = await intruder.status();
        if (stopped) return;
        setStatus(st);
        const more = await intruder.results(loadedRef.current, 500);
        if (stopped) return;
        if (more.length) {
          loadedRef.current += more.length;
          setRows((r) => [...r, ...more]);
        }
        if (st.done && loadedRef.current >= st.completed) {
          setRunning(false);
          stopped = true;
        }
      } catch {
        /* transient; keep polling */
      }
    };
    tick();
    const id = setInterval(tick, 500);
    return () => {
      stopped = true;
      clearInterval(id);
    };
  }, [running, runId]);

  const openInReplay = (row: AttemptRow) => {
    const counter = { i: 0 };
    const draft: ReplayDraft = {
      method,
      url: renderMarkers(url, row.replacements, counter),
      headersText: parsed.headers.map(([k, v]) => `${k}: ${renderMarkers(v, row.replacements, counter)}`).join('\n'),
      body: renderMarkers(body, row.replacements, counter),
    };
    onSendToReplay(draft, `Fuzzer #${row.index + 1}`);
  };

  const progressLabel = status
    ? `${status.completed}/${status.planned}${status.scope_skipped ? ` · ${status.scope_skipped} out-of-scope` : ''}`
    : '';

  return (
    <div className="workspace fuzzer" style={{ display: active ? 'flex' : 'none', flex: 1, flexDirection: 'column' }}>
      <div className="fuzzer-grid">
        {/* Request + positions */}
        <section className="fz-card" aria-label="Request template">
          <div className="fz-card-head">
            <span className="fz-title">Request</span>
            <button className="btn" onClick={addPosition} disabled={running} title="Wrap the selected text in a {{ }} position">
              <Plus size={12} /> Add position
            </button>
            <span className="fz-count">{positions} position{positions === 1 ? '' : 's'}</span>
          </div>
          <div className="fz-row">
            <select value={method} onChange={(e) => setMethod(e.target.value)} disabled={running} aria-label="Method">
              {REPLAY_METHODS.map((m) => (
                <option key={m}>{m}</option>
              ))}
            </select>
            <input
              ref={urlRef}
              className="fz-url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onFocus={() => (focusedRef.current = 'url')}
              disabled={running}
              placeholder="https://host/path?param={{value}}"
              spellCheck={false}
              aria-label="URL"
            />
          </div>
          <label className="fz-label">Headers (one per line, Name: value)</label>
          <textarea
            ref={headersRef}
            className="fz-area"
            rows={4}
            value={headersText}
            onChange={(e) => setHeadersText(e.target.value)}
            onFocus={() => (focusedRef.current = 'headers')}
            disabled={running}
            spellCheck={false}
          />
          <label className="fz-label">Body</label>
          <textarea
            ref={bodyRef}
            className="fz-area"
            rows={5}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            onFocus={() => (focusedRef.current = 'body')}
            disabled={running}
            spellCheck={false}
          />
        </section>

        {/* Attack + payloads */}
        <section className="fz-card" aria-label="Attack settings">
          <div className="fz-card-head">
            <span className="fz-title">Attack</span>
          </div>
          <div className="fz-controls">
            <label className="field">
              Type
              <select value={attackType} onChange={(e) => setAttackType(e.target.value as AttackType)} disabled={running}>
                <option value="sniper">Sniper (one set, each position in turn)</option>
                <option value="cluster_bomb">Cluster bomb (one set per position, all combos)</option>
              </select>
            </label>
            <label className="field">
              Concurrency
              <input type="number" min={1} max={32} value={concurrency} disabled={running} onChange={(e) => setConcurrency(Math.max(1, Math.min(32, +e.target.value || 1)))} />
            </label>
            <label className="field">
              Delay (ms)
              <input type="number" min={0} value={delayMs} disabled={running} onChange={(e) => setDelayMs(Math.max(0, +e.target.value || 0))} />
            </label>
            <label className="field">
              Max attempts
              <input type="number" min={1} value={maxAttempts} disabled={running} onChange={(e) => setMaxAttempts(Math.max(1, +e.target.value || 1))} />
            </label>
          </div>
          <label className="fz-check" style={{ marginTop: 6 }}>
            <input type="checkbox" checked={encodeUrl} disabled={running} onChange={(e) => setEncodeUrl(e.target.checked)} /> URL-encode payloads in URL positions (so spaces and special characters send correctly)
          </label>

          {attackType === 'sniper' ? (
            <PayloadEditor
              label="Payloads"
              value={payload}
              onChange={setPayload}
              disabled={running}
              onSuggest={() => setSuggestFor({ apply: (list) => setPayload((p) => ({ ...p, kind: 'list', list })) })}
            />
          ) : (
            <div className="fz-sets">
              {payloadSets.map((p, i) => (
                <PayloadEditor
                  key={i}
                  label={`Position ${i + 1}`}
                  value={p}
                  onChange={(v) => setPayloadSets((prev) => prev.map((x, j) => (j === i ? v : x)))}
                  disabled={running}
                  onSuggest={() => setSuggestFor({ apply: (list) => setPayloadSets((prev) => prev.map((x, j) => (j === i ? { ...x, kind: 'list', list } : x))) })}
                />
              ))}
              {positions === 0 && <p className="fz-hint">Mark positions in the request to configure their payload sets.</p>}
            </div>
          )}

          <div className="fz-actions">
            {running ? (
              <button className="btn btn-stop" onClick={cancel}>
                <Square size={11} fill="currentColor" /> Stop
              </button>
            ) : (
              <button className="btn btn-primary" onClick={start} disabled={!canStart} title={issues[0]}>
                <Play size={12} fill="currentColor" /> Start attack
              </button>
            )}
            <span className="fz-plan">{planned.toLocaleString()} request{planned === 1 ? '' : 's'} planned</span>
            {running && <Loader2 size={13} className="spin" />}
          </div>
          {issues.length > 0 && !running && <p className="fz-issue">{issues[0]}</p>}
          {error && <p className="fz-issue">{error}</p>}
        </section>
      </div>

      {/* Results */}
      <section className="fz-results" aria-label="Attack results">
        <div className="fz-results-head">
        {rows.length > 0 && rows.every((r) => r.status === 403) && (
          <div className="snapshot-banner" role="status">
            <strong>All attempts returned 403.</strong> That is usually bot protection, not the payload:
            solve the challenge once in Replay, press Import cookies, then retry with concurrency 2 and a
            small delay.
          </div>
        )}
          <span className="fz-title">Results</span>
          {status && <span className="fz-count">{progressLabel}</span>}
          {rows.length > 0 && <span className="fz-count" style={{ marginLeft: 'auto' }}>Click a row to open it in Replay</span>}
          {status?.error && status.error !== 'cancelled' && <span className="fz-issue">{status.error}</span>}
          {status?.error === 'cancelled' && <span className="fz-count">cancelled</span>}
        </div>
        <div className="fz-table-wrap">
          <table className="fz-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Payload</th>
                <th>Status</th>
                <th>Length</th>
                <th>Time</th>
                <th>Note</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.index} className="fz-row-click" onClick={() => openInReplay(r)} title="Open this request in a Replay tab">
                  <td className="fz-num">{r.index + 1}</td>
                  <td className="fz-payload" title={r.replacements.join(' | ')}>{r.replacements.join(' | ')}</td>
                  <td>{r.ok && r.status != null ? <span className={`status ${statusClass(r.status)}`}>{r.status}</span> : <span className="status s0">-</span>}</td>
                  <td className="fz-num">{r.total_bytes != null ? formatBytes(r.total_bytes) : '-'}</td>
                  <td className="fz-num">{r.duration_ms != null ? formatDuration(r.duration_ms) : '-'}</td>
                  <td className="fz-note">
                    {r.challenge
                      ? `challenge: ${r.challenge.vendor} ${r.challenge.kind}`
                      : r.ok
                        ? ''
                        : r.error_kind === 'scope'
                          ? 'out of scope'
                          : r.error_kind === 'blocked'
                            ? 'blocked: restricted address'
                            : r.error_message ?? r.error_kind ?? ''}
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="fz-empty">
                    {running ? 'Waiting for the first results…' : 'No results yet. Configure positions and payloads, then Start.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {suggestFor && (
        <SuggestModal
          requestText={requestText}
          onToast={onToast}
          onApply={(list) => {
            suggestFor.apply(list);
            setSuggestFor(null);
          }}
          onClose={() => setSuggestFor(null)}
        />
      )}
    </div>
  );
};

interface PayloadEditorProps {
  label: string;
  value: PayloadDraft;
  onChange: (v: PayloadDraft) => void;
  disabled: boolean;
  onSuggest?: () => void;
}

const PayloadEditor: React.FC<PayloadEditorProps> = ({ label, value, onChange, disabled, onSuggest }) => {
  const set = (patch: Partial<PayloadDraft>) => onChange({ ...value, ...patch });
  return (
    <div className="fz-payload-editor">
      <div className="fz-payload-head">
        <span className="fz-label">{label}</span>
        <div className="fz-kind">
          <button className={`fz-pill${value.kind === 'list' ? ' on' : ''}`} onClick={() => set({ kind: 'list' })} disabled={disabled}>
            List
          </button>
          <button className={`fz-pill${value.kind === 'number_range' ? ' on' : ''}`} onClick={() => set({ kind: 'number_range' })} disabled={disabled}>
            Numbers
          </button>
        </div>
        <select
          className="fz-preset-select"
          value=""
          disabled={disabled}
          title="Load a built-in payload list"
          onChange={(e) => {
            const list = PAYLOAD_LISTS.find((l) => l.name === e.target.value);
            if (list) onChange({ ...value, kind: 'list', list: list.values.join('\n') });
          }}
        >
          <option value="">Presets…</option>
          {PAYLOAD_LISTS.map((l) => (
            <option key={l.name} value={l.name}>
              {l.name}
            </option>
          ))}
        </select>
        {onSuggest && (
          <button className="fz-pill fz-ai" onClick={onSuggest} disabled={disabled} title="Suggest payloads with Drop AI">
            <Sparkles size={11} /> AI
          </button>
        )}
        <span className="fz-count">{payloadCount(value).toLocaleString()}</span>
      </div>
      {value.kind === 'list' ? (
        <>
          <textarea
            className="fz-area"
            rows={4}
            value={value.list}
            onChange={(e) => set({ list: e.target.value })}
            disabled={disabled}
            spellCheck={false}
            placeholder="One payload per line (paste a wordlist, or use Presets / AI)"
          />
          <span className="fz-hint">List: your own payloads, one per line. Paste SQLi/XSS wordlists here or load a Preset.</span>
        </>
      ) : (
        <>
        <div className="fz-range">
          <label className="field">
            From
            <input type="number" value={value.from} disabled={disabled} onChange={(e) => set({ from: +e.target.value || 0 })} />
          </label>
          <label className="field">
            To
            <input type="number" value={value.to} disabled={disabled} onChange={(e) => set({ to: +e.target.value || 0 })} />
          </label>
          <label className="field">
            Step
            <input type="number" value={value.step} disabled={disabled} onChange={(e) => set({ step: +e.target.value || 1 })} />
          </label>
        </div>
        <span className="fz-hint">Numbers: generates a sequence From → To by Step (e.g. 1→100 for ID enumeration). For text payloads, switch to List.</span>
        </>
      )}
    </div>
  );
};

const SUGGEST_SYSTEM =
  'You are a senior penetration tester helping on an AUTHORIZED engagement: the user owns the target or has written permission to test it. Build a practical fuzzing wordlist of standard, field-tested detection payloads, the kind published in the OWASP Web Security Testing Guide and the SecLists project, tailored to the exact injection point shown. ' +
  'Output format is strict and non-negotiable: ONE raw payload per line, ready to paste verbatim. No numbering, no bullets, no comments, no code fences, no blank lines, no explanation before or after. If you cannot comply with the format, output nothing.';

function buildPrompt(requestText: string): string {
  return (
    `Authorized web application security test. Below is the HTTP request; every fuzz position is marked with {{ }} and the text inside is the current base value.\n\n` +
    `${requestText}\n\n` +
    `For each marked position, infer its context (URL query parameter, path segment, header value, cookie, or JSON/form body field) and the parameter's likely purpose from its name, then produce the detection payloads that best probe that specific spot.\n\n` +
    `Cover the classes that fit the context, weighted toward the most likely: SQL injection (error-based, boolean, time-based), cross-site scripting (reflected and attribute-breakout), path/directory traversal, OS command injection, server-side template injection, LDAP/NoSQL injection, and authentication or logic bypass. Include a few encoding variants (URL, double-URL, unicode) where they matter, and keep the classic high-signal probes.\n\n` +
    `Return up to 40 payloads, deduplicated, ordered roughly by likelihood of a finding. One raw payload per line, nothing else.`
  );
}

function cleanPayloads(answer: string): string[] {
  return answer
    .split('\n')
    .map((l) =>
      l
        .replace(/^\s*[-*]\s+/, '')
        .replace(/^\s*\d+[.)]\s+/, '')
        .replace(/^`+|`+$/g, '')
        .trim(),
    )
    .filter((l) => l.length > 0 && !l.startsWith('```'));
}

interface SuggestModalProps {
  requestText: string;
  onApply: (list: string) => void;
  onClose: () => void;
  onToast: (m: string) => void;
}

const SuggestModal: React.FC<SuggestModalProps> = ({ requestText, onApply, onClose, onToast }) => {
  const [redact, setRedact] = useState(true);
  const [prompt, setPrompt] = useState(() => buildPrompt(redactSecrets(requestText)));
  const [sending, setSending] = useState(false);
  const [answer, setAnswer] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const toggleRedact = (v: boolean) => {
    setRedact(v);
    setPrompt(buildPrompt(v ? redactSecrets(requestText) : requestText));
  };

  const send = async () => {
    setSending(true);
    setError(null);
    setAnswer(null);
    try {
      setAnswer(await dropAi.complete(SUGGEST_SYSTEM, prompt));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSending(false);
    }
  };

  const parsed = answer ? cleanPayloads(answer) : [];

  return (
    <div className="fz-modal-backdrop" data-tauri-drag-region="false" onMouseDown={onClose}>
      <div className="fz-modal" role="dialog" aria-label="Suggest payloads with Drop AI" onMouseDown={(e) => e.stopPropagation()}>
        <div className="fz-modal-head">
          <span className="fz-title">
            <Sparkles size={13} /> Suggest payloads (Drop AI)
          </span>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <X size={14} />
          </button>
        </div>
        <label className="fz-check">
          <input type="checkbox" checked={redact} onChange={(e) => toggleRedact(e.target.checked)} /> Redact secrets before sending (recommended)
        </label>
        <span className="fz-label">This exact text will be sent to your model. Edit it if you like:</span>
        <textarea className="fz-area" rows={9} value={prompt} onChange={(e) => setPrompt(e.target.value)} spellCheck={false} />
        <div className="fz-actions">
          <button className="btn btn-primary" onClick={send} disabled={sending}>
            {sending ? (
              <>
                <Loader2 size={12} className="spin" /> Asking…
              </>
            ) : (
              <>
                <Sparkles size={12} /> Send to Drop AI
              </>
            )}
          </button>
          <span className="fz-plan">{parsed.length ? `${parsed.length} payloads parsed` : ''}</span>
        </div>
        {error && <p className="fz-issue">{error}</p>}
        {answer !== null && (
          <>
            <span className="fz-label">Suggested payloads</span>
            <textarea className="fz-area" rows={8} readOnly value={parsed.join('\n')} spellCheck={false} />
            <div className="fz-actions">
              <button
                className="btn btn-primary"
                disabled={!parsed.length}
                onClick={() => {
                  onApply(parsed.join('\n'));
                  onToast(`Inserted ${parsed.length} payload${parsed.length === 1 ? '' : 's'}.`);
                }}
              >
                Use as payloads
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
};
