import React, { useEffect, useState } from 'react';
import { Copy, Loader2, Sparkles, X } from 'lucide-react';
import { dropAi } from '../lib/transport';

/**
 * A one-click AI modal: it runs the given prompt as soon as it opens and shows the answer. Used for
 * triaging findings and drafting a report, where there is nothing for the user to configure first.
 */
interface Props {
  title: string;
  system: string;
  prompt: string;
  onClose: () => void;
  onToast: (m: string) => void;
}

export const AiResultModal: React.FC<Props> = ({ title, system, prompt, onClose, onToast }) => {
  const [sending, setSending] = useState(true);
  const [answer, setAnswer] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setSending(true);
    setError(null);
    try {
      setAnswer(await dropAi.complete(system, prompt));
    } catch (e) {
      setAnswer(null);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSending(false);
    }
  };

  // Run once on open so the user only clicks the one button that brought them here.
  useEffect(() => {
    run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const copy = async () => {
    if (!answer) return;
    try {
      await navigator.clipboard.writeText(answer);
      onToast('Copied.');
    } catch {
      /* ignore */
    }
  };

  return (
    <div className="fz-modal-backdrop" data-tauri-drag-region="false" onMouseDown={onClose}>
      <div className="fz-modal" role="dialog" aria-label={title} onMouseDown={(e) => e.stopPropagation()}>
        <div className="fz-modal-head">
          <span className="fz-title">
            <Sparkles size={13} /> {title}
          </span>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <X size={14} />
          </button>
        </div>
        {sending && (
          <p className="fz-hint">
            <Loader2 size={12} className="spin" /> Asking your model…
          </p>
        )}
        {error && <p className="fz-issue">{error}</p>}
        {answer !== null && <textarea className="fz-area" style={{ minHeight: 300 }} readOnly value={answer} spellCheck={false} />}
        <div className="fz-actions">
          <button className="btn btn-primary" onClick={run} disabled={sending}>
            {sending ? 'Working…' : 'Re-run'}
          </button>
          {answer !== null && (
            <button className="btn" onClick={copy}>
              <Copy size={12} /> Copy
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
