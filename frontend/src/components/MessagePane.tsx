import React, { useEffect, useMemo, useState } from 'react';
import { Check, Copy, Lock, Sparkles } from 'lucide-react';
import { TransactionRecord } from '../types';
import {
  buildRawHead,
  bytesToText,
  classifyBody,
  copyText,
  decodeBody,
  DecodedBody,
  extractParams,
  formatBytes,
  Header,
  headerValue,
  looksBinary,
  parseMessage,
  parseOmitted,
  describeOmission,
  isInterrupted,
  OmittedBody,
  redactedHeaderNames,
} from '../lib/http';
import { useStoredState } from '../lib/useStoredState';
import { analyzeResponse, Finding, Severity, topSeverity } from '../lib/findings';
import { redactSecrets } from '../lib/redact';
import { AiResultModal } from './AiResultModal';
import { HexView, hexRows, jsonLines, Lines, MAX_LINES, withRedactions } from './CodeView';

const TRIAGE_SYSTEM =
  'You are a web security tester triaging passive scan findings during an AUTHORIZED assessment. Note the technology you can fingerprint from the evidence. For each finding give one compact block: the finding name, a verdict (Likely true positive / Likely false positive / Needs manual check), a priority (High / Medium / Low), the CVE or CWE id when one clearly applies (only when you are confident, never invented), and a one-line remediation. No preamble, no conclusion.';
const REPORT_SYSTEM =
  'You are a penetration tester writing a concise findings report during an AUTHORIZED assessment. Output GitHub-flavoured Markdown only: a one-paragraph summary, then a "## Findings" section with one "### " subsection per finding containing Severity, Description (cite the CVE or CWE id when one clearly applies, never invented), Impact, and Remediation. Professional and ready to paste. No preamble before the Markdown.';

export type Side = 'request' | 'response';
type View = 'raw' | 'headers' | 'body' | 'params' | 'issues' | 'hex';

interface MessagePaneProps {
  side: Side;
  record: TransactionRecord;
  /** Title slot: a plain label, or the Request/Response switch in tabbed layout. */
  title: React.ReactNode;
  onCopied: (what: string) => void;
}

function headLines(startLine: string, headers: Header[]): React.ReactNode[] {
  return [
    <span className="start">{startLine}</span>,
    ...headers.map(([k, v]) => (
      <>
        <span className="hname">{k}</span>
        <span className="hsep">: </span>
        {withRedactions(v)}
      </>
    )),
  ];
}

// HTTP date headers are always sent in GMT. Show the equivalent in the viewer's own timezone
// as a convenience, without touching the original value (evidence stays exactly as on the wire).
const HTTP_DATE_HEADERS = new Set(['date', 'expires', 'last-modified', 'if-modified-since', 'if-unmodified-since']);
function localDateHint(name: string, value: string): string | null {
  if (!HTTP_DATE_HEADERS.has(name.trim().toLowerCase())) return null;
  const d = new Date(value.trim());
  if (Number.isNaN(d.getTime())) return null;
  const offsetMin = -d.getTimezoneOffset(); // minutes east of UTC, for the viewer
  const zone = offsetMin === 420 ? 'WIB' : offsetMin === 480 ? 'WITA' : offsetMin === 540 ? 'WIT' : 'lokal';
  const t = d.toLocaleString('id-ID', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
  return `${t} ${zone}`;
}

export const MessagePane: React.FC<MessagePaneProps> = ({ side, record, title, onCopied }) => {
  const [view, setView] = useStoredState<View>(`view.${side}`, side === 'request' ? 'raw' : 'body');
  const [pretty, setPretty] = useStoredState<boolean>('json.pretty', true);
  const [copied, setCopied] = useState(false);

  const headers: Header[] = side === 'request' ? record.request_headers : record.response_headers;
  const msg = useMemo(() => parseMessage(side === 'request' ? record.request_body : record.response_body), [record, side]);
  const startLine = msg.startLine || (side === 'request' ? `${record.method} ${record.url} HTTP/1.1` : `HTTP/1.1 ${record.status_code}`);
  const redacted = redactedHeaderNames(headers);
  const omitted = useMemo(() => parseOmitted(msg.body), [msg]);
  const params = useMemo(() => (side === 'request' ? extractParams(record.url, msg.body, headers) : []), [record, side, msg, headers]);
  const contentType = headerValue(headers, 'content-type') ?? (side === 'response' ? record.content_type : undefined);
  // For passive response checks: the request's parameter values, to detect reflected input.
  const reqParamValues = useMemo(
    () => (side === 'response' ? extractParams(record.url, parseMessage(record.request_body).body, record.request_headers).map((p) => p.value) : []),
    [record, side],
  );

  const [decoded, setDecoded] = useState<DecodedBody | null>(null);
  useEffect(() => {
    let live = true;
    setDecoded(null);
    // An omission record is not a body: never try to decompress or dechunk it.
    if (parseOmitted(msg.body)) setDecoded({ bytes: new Uint8Array(), transforms: [] });
    else decodeBody(msg.body, headers).then((d) => live && setDecoded(d));
    return () => {
      live = false;
    };
  }, [msg, headers]);

  // Never fall back to a view that has nothing to show for this side.
  const effective: View =
    view === 'params' && side === 'response' ? 'body' : view === 'issues' && side === 'request' ? 'raw' : view;

  const bodyKind = decoded ? (decoded.undecoded ? 'binary' : classifyBody(decoded.bytes, contentType)) : null;
  const bodyText = decoded && bodyKind !== 'binary' && bodyKind !== 'image' ? bytesToText(decoded.bytes) : '';
  const parsedJson = useMemo(() => {
    if (bodyKind !== 'json') return undefined;
    try {
      return JSON.parse(bodyText) as unknown;
    } catch {
      return undefined;
    }
  }, [bodyKind, bodyText]);

  const findings: Finding[] = useMemo(
    () => (side === 'response' ? analyzeResponse({ url: record.url, status: record.status_code, headers, body: bodyText, paramValues: reqParamValues }) : []),
    [side, record, headers, bodyText, reqParamValues],
  );
  const findingsSeverity = topSeverity(findings);
  const [ai, setAi] = useState<{ title: string; system: string; prompt: string } | null>(null);
  const aiContext = () => {
    const target = `Target: ${record.method} ${record.url} -> ${record.status_code}${contentType ? ` (${contentType})` : ''}`;
    const hdrs = redactSecrets(headers.map(([k, v]) => `${k}: ${v}`).join('\n'));
    const list = findings.map((f, i) => `${i + 1}. [${f.severity}] ${f.title}: ${f.detail}`).join('\n');
    return `${target}\n\nResponse headers:\n${hdrs}\n\nPassive findings:\n${list}`;
  };

  const rawBodyIsBinary = looksBinary(msg.body);
  const rawText = useMemo(() => {
    const head = buildRawHead(startLine, headers);
    if (!msg.hasHead) return head;
    return `${head}\r\n\r\n${rawBodyIsBinary ? '' : bytesToText(msg.body)}`;
  }, [startLine, headers, msg, rawBodyIsBinary]);

  const copyCurrent = async () => {
    let text = '';
    switch (effective) {
      case 'raw':
        text = rawText;
        break;
      case 'headers':
        text = headers.map(([k, v]) => `${k}: ${v}`).join('\n');
        break;
      case 'body':
        text = omitted ? bytesToText(msg.body) : parsedJson !== undefined && pretty ? JSON.stringify(parsedJson, null, 2) : bodyText;
        break;
      case 'params':
        text = params.map((p) => `${p.name}=${p.value}`).join('\n');
        break;
      case 'hex':
        text = hexRows(msg.body)
          .map((r) => `${r.off}  ${r.hex} ${r.ascii}`)
          .join('\n');
        break;
    }
    if (await copyText(text)) {
      setCopied(true);
      onCopied(`${side === 'request' ? 'Request' : 'Response'} ${effective} copied`);
      setTimeout(() => setCopied(false), 1200);
    }
  };

  const tabs: { id: View; label: string; count?: number; hidden?: boolean; countSeverity?: Severity }[] = [
    { id: 'raw', label: 'Raw' },
    { id: 'headers', label: 'Headers', count: headers.length },
    { id: 'body', label: 'Body' },
    { id: 'params', label: 'Params', count: params.length, hidden: side === 'response' },
    { id: 'issues', label: 'Issues', count: findings.length, hidden: side === 'request', countSeverity: findingsSeverity ?? undefined },
    { id: 'hex', label: 'Hex' },
  ];

  const tabId = (v: View) => `${side}-${record.id}-${v}`;

  const onTabKey = (e: React.KeyboardEvent) => {
    const visibleTabs = tabs.filter((t) => !t.hidden).map((t) => t.id);
    const i = visibleTabs.indexOf(effective);
    if (e.key === 'ArrowRight') setView(visibleTabs[(i + 1) % visibleTabs.length]);
    else if (e.key === 'ArrowLeft') setView(visibleTabs[(i - 1 + visibleTabs.length) % visibleTabs.length]);
    else return;
    e.preventDefault();
  };

  let content: React.ReactNode;
  if (effective === 'raw') {
    if (!msg.hasHead) {
      content = (
        <>
          <div className="content-note">The captured bytes have no end-of-headers marker, so only the parsed headers are shown.</div>
          <Lines lines={headLines(startLine, headers)} />
        </>
      );
    } else {
      const body: React.ReactNode[] = omitted
        ? [<span className="placeholder">{`[body not stored: ${omitted.reason}]`}</span>]
        : rawBodyIsBinary
        ? [<span className="placeholder">{`[binary body, ${formatBytes(msg.body.length)}; open Hex to read it]`}</span>]
        : msg.body.length
          ? bytesToText(msg.body).split(/\r?\n/).slice(0, MAX_LINES)
          : [];
      content = <Lines lines={[...headLines(startLine, headers), '', ...body]} />;
    }
  } else if (effective === 'headers') {
    content = headers.length ? (
      <table className="kv">
        <thead>
          <tr>
            <th>Name</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          {headers.map(([k, v], i) => {
            const local = localDateHint(k, v);
            return (
              <tr key={i}>
                <td className="k">{k}</td>
                <td>
                  {withRedactions(v)}
                  {local && (
                    <span className="hdr-local" title="Waktu server (GMT) dalam zona waktu Anda. Nilai asli di sebelah kiri tidak diubah.">
                      {' · '}{local}
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    ) : (
      <div className="body-empty">No headers were captured for this {side}.</div>
    );
  } else if ((effective === 'body' || effective === 'hex') && omitted) {
    content = <OmittedNote omitted={omitted} />;
  } else if (effective === 'body') {
    if (!decoded) {
      content = <div className="body-empty">Decoding…</div>;
    } else if (bodyKind === 'empty') {
      content = (
        <div className="body-empty">
          This {side} has no body.
          {side === 'request' && ['GET', 'HEAD', 'OPTIONS', 'DELETE'].includes(record.method.toUpperCase()) && ` ${record.method.toUpperCase()} requests usually carry none.`}
        </div>
      );
    } else {
      const notes: string[] = [...decoded.transforms];
      if (decoded.undecoded) notes.push(`${decoded.undecoded} encoding can't be decoded here; showing bytes as captured`);
      const isHtml = (contentType ?? '').toLowerCase().includes('html');
      content = (
        <>
          {(notes.length > 0 || bodyKind === 'json' || isHtml) && (
            <div className="content-note">
              {bodyKind === 'json' && (
                <span className="segmented" role="group" aria-label="JSON display">
                  <button aria-pressed={pretty} onClick={() => setPretty(true)}>
                    Pretty
                  </button>
                  <button aria-pressed={!pretty} onClick={() => setPretty(false)}>
                    Original
                  </button>
                </span>
              )}
              {isHtml && <span>Markup is shown as source. DropSuite never renders captured HTML or runs its scripts.</span>}
              {notes.length > 0 && <span>Shown {notes.join(', ')}. Raw and Hex keep the bytes as captured.</span>}
            </div>
          )}
          {bodyKind === 'image' ? (
            <ImagePreview bytes={decoded.bytes} contentType={contentType ?? 'image/png'} />
          ) : bodyKind === 'binary' ? (
            <div className="msg-state">
              <strong>Binary body, {formatBytes(decoded.bytes.length)}.</strong> {contentType ? `Content-Type is ${contentType}. ` : ''}Open Hex to read the bytes.
            </div>
          ) : bodyKind === 'json' && pretty && parsedJson !== undefined ? (
            <Lines lines={jsonLines(parsedJson)} />
          ) : (
            <Lines lines={bodyText.split(/\r?\n/).slice(0, MAX_LINES)} />
          )}
        </>
      );
    }
  } else if (effective === 'params') {
    content = params.length ? (
      <table className="kv">
        <thead>
          <tr>
            <th>Source</th>
            <th>Name</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          {params.map((p, i) => (
            <tr key={i}>
              <td className="src">{p.source === 'query' ? 'URL query' : 'Form body'}</td>
              <td className="k">{p.name}</td>
              <td>{p.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    ) : (
      <div className="body-empty">No URL query or form-encoded body parameters in this request.</div>
    );
  } else if (effective === 'issues') {
    content = findings.length ? (
      <>
        <div className="findings-actions">
          <button className="fz-pill fz-ai" onClick={() => setAi({ title: 'Triage findings (Drop AI)', system: TRIAGE_SYSTEM, prompt: aiContext() })}>
            <Sparkles size={11} /> Triage with AI
          </button>
          <button className="fz-pill fz-ai" onClick={() => setAi({ title: 'Draft report (Drop AI)', system: REPORT_SYSTEM, prompt: aiContext() })}>
            <Sparkles size={11} /> Draft report
          </button>
        </div>
        <ul className="findings">
        {findings.map((f, i) => (
          <li key={i} className={`finding sev-${f.severity}`}>
            <span className={`sev-badge sev-${f.severity}`}>{f.severity}</span>
            <div className="finding-text">
              <strong>{f.title}</strong>
              <span>{f.detail}</span>
            </div>
          </li>
        ))}
        </ul>
      </>
    ) : (
      <div className="body-empty">No passive issues found. This is a quick read-only check of headers and body, not a full audit.</div>
    );
  } else {
    content = msg.body.length ? <HexView bytes={msg.body} /> : <div className="body-empty">This {side} has no body bytes.</div>;
  }

  return (
    <section className="msg" aria-label={side === 'request' ? 'Request' : 'Response'}>
      <div className="msg-head">
        {title}
        <div className="views" role="tablist" aria-label={`${side} view`} onKeyDown={onTabKey}>
          {tabs
            .filter((t) => !t.hidden)
            .map((t) => (
              <button
                key={t.id}
                id={tabId(t.id)}
                role="tab"
                className="view-tab"
                aria-selected={effective === t.id}
                tabIndex={effective === t.id ? 0 : -1}
                onClick={() => setView(t.id)}
              >
                {t.label}
                {t.count !== undefined && <span className={`count${t.countSeverity ? ` count-sev sev-${t.countSeverity}` : ''}`}>{t.count}</span>}
              </button>
            ))}
        </div>
        <div className="msg-tools">
          {redacted.length > 0 && (
            <span className="redaction-note" title={`Redacted before storage: ${redacted.join(', ')}`}>
              <Lock size={11} />
              {redacted.length} redacted
            </span>
          )}
          <button className={`icon-btn${copied ? ' done' : ''}`} onClick={copyCurrent} aria-label={`Copy ${side} ${effective}`} title={`Copy ${effective}`}>
            {copied ? <Check size={14} /> : <Copy size={14} />}
          </button>
        </div>
      </div>
      <div className="msg-content" role="tabpanel" aria-labelledby={tabId(effective)} tabIndex={0}>
        {content}
      </div>
      {ai && <AiResultModal title={ai.title} system={ai.system} prompt={ai.prompt} onClose={() => setAi(null)} onToast={onCopied} />}
    </section>
  );
};

const ImagePreview: React.FC<{ bytes: Uint8Array; contentType: string }> = ({ bytes, contentType }) => {
  const [url, setUrl] = useState<string | null>(null);
  const [dims, setDims] = useState<string>('');
  useEffect(() => {
    // Raster formats only; SVG and other markup never reach this path.
    const u = URL.createObjectURL(new Blob([bytes as BlobPart], { type: contentType.split(';')[0] }));
    setUrl(u);
    return () => URL.revokeObjectURL(u);
  }, [bytes, contentType]);
  return (
    <div className="image-preview">
      {url && <img src={url} alt="Captured response image" onLoad={(e) => setDims(`${e.currentTarget.naturalWidth} × ${e.currentTarget.naturalHeight} px`)} />}
      <div className="meta">
        {contentType.split(';')[0]} · {formatBytes(bytes.length)}
        {dims && ` · ${dims}`}
      </div>
    </div>
  );
};

/** Shown in place of a body the engine did not store (fail-closed policy). */
const OmittedNote: React.FC<{ omitted: OmittedBody }> = ({ omitted }) => (
  <>
    <div className="msg-state">
      <strong>Body not stored.</strong> {describeOmission(omitted.reason)}{' '}
      {isInterrupted(omitted.reason)
        ? 'DropSuite never stores part of a body, so only this summary was kept.'
        : 'DropSuite keeps a body only when it can read it and check it for credentials, so this one was replaced by a summary. The traffic itself was delivered unchanged.'}
    </div>
    <table className="kv">
      <tbody>
        <tr>
          <td className="k">Content type</td>
          <td>{omitted.contentType || 'none declared'}</td>
        </tr>
        <tr>
          <td className="k">Observed length</td>
          <td>{omitted.length.toLocaleString()} bytes</td>
        </tr>
        <tr>
          <td className="k">SHA-256</td>
          <td>
            {omitted.sha256 ??
              (omitted.length < 64 ? 'Not recorded for bodies under 64 bytes' : 'Not recorded (incomplete body)')}
          </td>
        </tr>
      </tbody>
    </table>
  </>
);
