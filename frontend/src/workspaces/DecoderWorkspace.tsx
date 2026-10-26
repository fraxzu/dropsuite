import React, { useRef, useState } from 'react';
import { ArrowUp, Copy, Trash2 } from 'lucide-react';
import { applyTransform, TransformId, TRANSFORM_GROUPS } from '../lib/codec';

interface DecoderWorkspaceProps {
  active: boolean;
  onToast: (msg: string) => void;
}

export const DecoderWorkspace: React.FC<DecoderWorkspaceProps> = ({ active, onToast }) => {
  const [input, setInput] = useState('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwibmFtZSI6IkRyb3BTdWl0ZSJ9.sig');
  const [output, setOutput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [last, setLast] = useState<TransformId | null>(null);
  const outRef = useRef<HTMLTextAreaElement>(null);

  const run = (id: TransformId) => {
    try {
      setOutput(applyTransform(id, input));
      setError(null);
      setLast(id);
    } catch (e) {
      setOutput('');
      setError(e instanceof Error ? e.message : String(e));
      setLast(id);
    }
  };

  const useAsInput = () => {
    if (!output) return;
    setInput(output);
    setOutput('');
    setLast(null);
    setError(null);
  };

  const copyOut = async () => {
    if (!output) return;
    try {
      await navigator.clipboard.writeText(output);
      onToast('Output copied.');
    } catch {
      outRef.current?.select();
      document.execCommand('copy');
      onToast('Output copied.');
    }
  };

  const clearAll = () => {
    setInput('');
    setOutput('');
    setError(null);
    setLast(null);
  };

  return (
    <div className="workspace decoder" style={{ display: active ? 'flex' : 'none', flex: 1, flexDirection: 'column' }}>
      <div className="dec-grid">
        <section className="fz-card" aria-label="Input">
          <div className="fz-card-head">
            <span className="fz-title">Input</span>
            <span className="fz-count">{input.length} char{input.length === 1 ? '' : 's'}</span>
            <button className="btn" onClick={clearAll} title="Clear input and output" style={{ marginLeft: 'auto' }}>
              <Trash2 size={12} /> Clear
            </button>
          </div>
          <textarea className="fz-area dec-area" value={input} onChange={(e) => setInput(e.target.value)} spellCheck={false} aria-label="Input text" />
          <div className="dec-ops">
            {TRANSFORM_GROUPS.map((g) => (
              <div className="dec-op-group" key={g.label}>
                <span className="fz-label">{g.label}</span>
                <div className="dec-op-buttons">
                  {g.items.map((it) => (
                    <button key={it.id} className={`fz-pill${last === it.id ? ' on' : ''}`} onClick={() => run(it.id)} title={`${g.label}: ${it.label}`}>
                      {it.label}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="fz-card" aria-label="Output">
          <div className="fz-card-head">
            <span className="fz-title">Output</span>
            <span className="fz-count">{output.length} char{output.length === 1 ? '' : 's'}</span>
            <button className="btn" onClick={useAsInput} disabled={!output} title="Send the output back to the input to chain transforms" style={{ marginLeft: 'auto' }}>
              <ArrowUp size={12} /> Use as input
            </button>
            <button className="btn" onClick={copyOut} disabled={!output} title="Copy output">
              <Copy size={12} /> Copy
            </button>
          </div>
          {error ? (
            <div className="dec-error">{error}</div>
          ) : (
            <textarea ref={outRef} className="fz-area dec-area" value={output} readOnly spellCheck={false} placeholder="Pick a transform to see the result here." aria-label="Output text" />
          )}
        </section>
      </div>
      <p className="fz-hint dec-foot">All transforms run locally in the app. Nothing is sent anywhere. Chain steps with “Use as input”.</p>
    </div>
  );
};
