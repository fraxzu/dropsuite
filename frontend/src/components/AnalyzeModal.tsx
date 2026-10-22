import React, { useMemo, useState } from 'react';
import { Loader2, Sparkles, X } from 'lucide-react';
import { dropAi } from '../lib/transport';
import { redactSecrets } from '../lib/redact';
import { extractHtmlSummary, splitHeadBody } from '../lib/htmlExtract';

const ANALYZE_SYSTEM =
  'You are a senior web application penetration tester reviewing one HTTP request/response during an AUTHORIZED assessment: the user owns the target or has written permission to test it. ' +
  'Point out concrete security weaknesses visible in this exchange: missing or weak security headers, information disclosure, injection / XSS / SSTI indicators, authentication or session problems, insecure cookies, CORS issues, and business-logic hints. ' +
  'For each finding give four short parts: what it is, why it matters, how to confirm it (a specific next request or payload), and the fix. Be specific to what is actually shown. ' +
  'If nothing notable is present, say so plainly, then list the highest-value next requests to probe this target (endpoints, parameters, methods). Keep it practical and skimmable.';

const RAW_CAP = 40000;

type Mode = 'combined' | 'smart' | 'raw';

const MODE_LABEL: Record<Mode, string> = { combined: 'Combined', smart: 'Smart', raw: 'Raw' };
const MODE_HINT: Record<Mode, string> = {
  combined: 'Headers + a summary of forms/inputs/scripts/links + a body snippet. Compact and accurate (recommended).',
  smart: 'Headers + a summary of the security-relevant HTML (forms, inputs, scripts, endpoints, comments). Smallest.',
  raw: `Headers + the raw body, up to ${(RAW_CAP / 1000).toFixed(0)}KB. Most complete, most tokens.`,
};

interface Props {
  requestText: string;
  /** The full raw response (status line + headers + body). */
  responseText: string;
  contentType?: string;
  onClose: () => void;
  onToast: (m: string) => void;
}

function buildResponsePart(mode: Mode, responseText: string): string {
  const { head, body } = splitHeadBody(responseText);
  if (mode === 'raw') return responseText.slice(0, RAW_CAP);
  if (mode === 'smart') return `${head}\n\n[Body summary]\n${extractHtmlSummary(body)}`;
  // combined
  return `${head}\n\n[Body summary]\n${extractHtmlSummary(body, 4000)}\n\n[Body snippet]\n${body.slice(0, 5000)}`;
}

export const AnalyzeModal: React.FC<Props> = ({ requestText, responseText, onClose, onToast }) => {
  const [mode, setMode] = useState<Mode>('combined');
  const [redact, setRedact] = useState(true);
  const [sending, setSending] = useState(false);
  const [answer, setAnswer] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const payload = useMemo(() => {
    const resp = buildResponsePart(mode, responseText);
    const req = redact ? redactSecrets(requestText) : requestText;
    const r = redact ? redactSecrets(resp) : resp;
    return `AUTHORIZED security review. Analyze this HTTP exchange.\n\n=== REQUEST ===\n${req}\n\n=== RESPONSE ===\n${r}`;
  }, [mode, redact, requestText, responseText]);

  const run = async () => {
    setSending(true);
    setError(null);
    setAnswer(null);
    try {
      setAnswer(await dropAi.complete(ANALYZE_SYSTEM, payload));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSending(false);
    }
  };

  const copy = async () => {
    if (!answer) return;
    try {
      await navigator.clipboard.writeText(answer);
      onToast('Analysis copied.');
    } catch {
      /* ignore */
    }
  };

  const sizeKb = (payload.length / 1024).toFixed(1);

  return (
    <div className="fz-modal-backdrop" onMouseDown={onClose}>
      <div className="fz-modal" role="dialog" aria-label="Analyze with Drop AI" onMouseDown={(e) => e.stopPropagation()}>
        <div className="fz-modal-head">
          <span className="fz-title">
            <Sparkles size={13} /> Analyze with Drop AI
          </span>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <X size={14} />
          </button>
        </div>

        <div className="analyze-modes">
          <span className="field-label">What to send</span>
          <div className="fz-kind">
            {(['combined', 'smart', 'raw'] as Mode[]).map((m) => (
              <button key={m} className={`fz-pill${mode === m ? ' on' : ''}`} onClick={() => setMode(m)}>
                {MODE_LABEL[m]}
              </button>
            ))}
          </div>
          <span className="fz-count">~{sizeKb} KB</span>
        </div>
        <p className="fz-hint">{MODE_HINT[mode]}</p>

        <label className="fz-check">
          <input type="checkbox" checked={redact} onChange={(e) => setRedact(e.target.checked)} /> Redact secrets before sending (recommended)
        </label>

        {!answer && (
          <div className="fz-actions">
            <button className="btn btn-primary" onClick={run} disabled={sending}>
              {sending ? (
                <>
                  <Loader2 size={12} className="spin" /> Analyzing…
                </>
              ) : (
                <>
                  <Sparkles size={12} /> Analyze
                </>
              )}
            </button>
          </div>
        )}
        {error && <p className="fz-issue">{error}</p>}
        {answer && (
          <>
            <textarea className="fz-area" style={{ minHeight: 300 }} readOnly value={answer} spellCheck={false} />
            <div className="fz-actions">
              <button className="btn btn-primary" onClick={run} disabled={sending}>
                {sending ? 'Working…' : 'Re-run'}
              </button>
              <button className="btn" onClick={copy}>
                Copy
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
};
