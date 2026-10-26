import React, { useEffect, useRef, useState } from 'react';
import { ChevronDown } from 'lucide-react';
import { DropAiConfig, DropAiProvider, DropAiStatus } from '../types';
import { dropAi } from '../lib/transport';

interface Props {
  onClose: () => void;
  onToast?: (msg: string) => void;
}

const BASE_HINT: Record<DropAiProvider, string> = {
  'open-ai-compatible': 'e.g. https://api.openai.com/v1 · http://localhost:11434/v1 (Ollama) · OpenRouter, Groq, Together',
  'anthropic-compatible': 'e.g. https://api.anthropic.com (no /v1; DropSuite adds /v1/messages)',
};

export const DropAiPanel: React.FC<Props> = ({ onClose, onToast }) => {
  const [cfg, setCfg] = useState<DropAiConfig | null>(null);
  const [hasKey, setHasKey] = useState(false);
  const [protection, setProtection] = useState('');
  const [keyInput, setKeyInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [models, setModels] = useState<string[]>([]);
  const [detecting, setDetecting] = useState(false);
  const root = useRef<HTMLDivElement>(null);

  const apply = (s: DropAiStatus) => {
    setCfg({ provider: s.provider, base_url: s.base_url, model: s.model, temperature: s.temperature, max_tokens: s.max_tokens });
    setHasKey(s.has_key);
    setProtection(s.key_protection);
  };

  const fetchModels = async (c: DropAiConfig, announce = false) => {
    setDetecting(true);
    setError(null);
    try {
      const list = await dropAi.listModels(c);
      setModels(list);
      if (announce) onToast?.(`Found ${list.length} model${list.length === 1 ? '' : 's'}.`);
      // If the current model isn't in the list, default to the first detected one.
      setCfg((prev) => (prev && !list.includes(prev.model) && list.length ? { ...prev, model: list[0] } : prev));
    } catch (e) {
      setModels([]);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setDetecting(false);
    }
  };

  useEffect(() => {
    dropAi
      .getConfig()
      .then((s) => {
        apply(s);
        if (s.has_key && s.base_url.trim()) {
          fetchModels({ provider: s.provider, base_url: s.base_url, model: s.model, temperature: s.temperature, max_tokens: s.max_tokens });
        }
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
      }
    };
    const onDown = (e: MouseEvent) => {
      if (root.current && !root.current.contains(e.target as Node) && !(e.target as Element).closest?.('[data-dropai-toggle]')) onClose();
    };
    window.addEventListener('keydown', onKey, true);
    window.addEventListener('mousedown', onDown);
    return () => {
      window.removeEventListener('keydown', onKey, true);
      window.removeEventListener('mousedown', onDown);
    };
  }, [onClose]);

  const set = (patch: Partial<DropAiConfig>) => {
    if (!cfg) return;
    // Base URL or provider change makes the detected list stale.
    if (patch.base_url !== undefined || patch.provider !== undefined) setModels([]);
    setCfg({ ...cfg, ...patch });
  };

  const saveConfig = async () => {
    if (!cfg) return;
    setBusy(true);
    setError(null);
    try {
      apply(await dropAi.setConfig(cfg));
      onToast?.('Drop AI settings saved.');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const saveKey = async () => {
    setBusy(true);
    setError(null);
    try {
      const stored = await dropAi.setKey(keyInput);
      setHasKey(stored);
      setKeyInput('');
      onToast?.(stored ? 'Key saved (protected at rest).' : 'Key cleared.');
      if (stored && cfg && cfg.base_url.trim()) fetchModels(cfg, true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const clearKey = async () => {
    setBusy(true);
    setError(null);
    try {
      await dropAi.clearKey();
      setHasKey(false);
      setKeyInput('');
      onToast?.('Key cleared.');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const test = async () => {
    setBusy(true);
    setError(null);
    setTestResult(null);
    try {
      // Save current config first so the test uses what's on screen.
      await dropAi.setConfig(cfg!);
      const reply = await dropAi.test();
      setTestResult(reply.trim().slice(0, 200) || '(empty reply)');
      onToast?.('Drop AI responded.');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div ref={root} className="popover dropai-panel" role="dialog" aria-label="Drop AI settings" data-tauri-drag-region="false" style={{ width: 420, maxHeight: '85vh', overflowY: 'auto' }}>
      <div className="popover-title">Drop AI: bring your own key</div>
      <p className="popover-note" style={{ marginTop: 0 }}>
        Your model, your key. Calls go straight to your endpoint, with no DropSuite server in between. The key is stored {protection ? `with ${protection}` : 'protected at rest'} and never logged.
      </p>

      {cfg && (
        <>
          <label className="field" style={{ gridTemplateColumns: '92px 1fr' }}>
            <span className="field-label">Provider</span>
            <select value={cfg.provider} disabled={busy} onChange={(e) => set({ provider: e.target.value as DropAiProvider })}>
              <option value="open-ai-compatible">OpenAI-compatible</option>
              <option value="anthropic-compatible">Anthropic-compatible</option>
            </select>
          </label>
          <label className="field" style={{ gridTemplateColumns: '92px 1fr' }}>
            <span className="field-label">Base URL</span>
            <input className="text-input mono" value={cfg.base_url} disabled={busy} onChange={(e) => set({ base_url: e.target.value })} spellCheck={false} />
            <span className="field-hint" style={{ gridColumn: 2 }}>{BASE_HINT[cfg.provider]}</span>
          </label>
          <div className="field" style={{ gridTemplateColumns: '92px 1fr auto' }}>
            <span className="field-label">Model</span>
            {models.length > 0 ? (
              <ModelPicker value={cfg.model} options={models} disabled={busy} onChange={(m) => set({ model: m })} />
            ) : (
              <input className="text-input mono" value={cfg.model} disabled={busy} onChange={(e) => set({ model: e.target.value })} spellCheck={false} placeholder="gpt-4o-mini · claude-sonnet-4-5 · llama-3.1-70b" />
            )}
            <button type="button" className="btn" onClick={() => fetchModels(cfg, true)} disabled={busy || detecting || !hasKey} title={hasKey ? 'Fetch the model list from your endpoint' : 'Save a key first'}>
              {detecting ? 'Detecting…' : 'Detect'}
            </button>
          </div>
          {models.length > 0 && (
            <span className="field-hint" style={{ display: 'block', marginTop: -6, marginBottom: 8 }}>
              {models.length} models from your endpoint. Pick one, or Detect again after changing the base URL.
            </span>
          )}
          {cfg.model && /claude|gpt|codex|openai|gemini|o[1-4]\b/i.test(cfg.model) && (
            <p className="dropai-warn">
              Heads up: routing a model like <strong>{cfg.model}</strong> through a third-party endpoint can break the
              provider's terms of service and may get your account flagged or banned. Only use a model you are allowed to
              access this way.
            </p>
          )}
          <div style={{ display: 'flex', gap: 10 }}>
            <label className="field" style={{ gridTemplateColumns: '92px 1fr', flex: 1 }}>
              <span className="field-label" title="Randomness of the reply. 0 = focused and repeatable; higher = more varied.">Temperature</span>
              <input type="number" step={0.1} min={0} max={2} className="text-input mono" value={cfg.temperature} disabled={busy} onChange={(e) => set({ temperature: Math.max(0, Math.min(2, +e.target.value || 0)) })} />
            </label>
            <label className="field" style={{ gridTemplateColumns: '80px 1fr', flex: 1 }}>
              <span className="field-label" title="Maximum length of the model's reply (not your prompt). Higher = longer answers and more cost. Reasoning models need more.">Max tokens</span>
              <input type="number" min={1} list="maxtok-presets" className="text-input mono" value={cfg.max_tokens} disabled={busy} onChange={(e) => set({ max_tokens: Math.max(1, +e.target.value || 1) })} />
              <datalist id="maxtok-presets">
                <option value="512" />
                <option value="1024" />
                <option value="2048" />
                <option value="4096" />
                <option value="8192" />
                <option value="16384" />
              </datalist>
            </label>
          </div>
          <div className="maxtok-presets-row">
            <span className="field-hint">Max tokens presets:</span>
            {[1024, 2048, 4096, 8192, 16384].map((n) => (
              <button type="button" key={n} className={`fz-pill${cfg.max_tokens === n ? ' on' : ''}`} disabled={busy} onClick={() => set({ max_tokens: n })}>
                {n >= 1024 ? `${n / 1024}k` : n}
              </button>
            ))}
          </div>
          <span className="field-hint" style={{ display: 'block', marginBottom: 8 }}>
            <strong>Temperature</strong> 0 to 2: how random the reply is. 0 is focused &amp; repeatable (best for precise analysis), ~0.7 is more creative.
            &nbsp;·&nbsp; <strong>Max tokens</strong>: cap on the reply length (≈¾ word each); higher costs more.
          </span>

          <div className="popover-actions" style={{ marginBottom: 12 }}>
            <button type="button" className="btn" onClick={test} disabled={busy || !hasKey} title={hasKey ? 'Send a tiny test prompt' : 'Add a key first'}>
              {busy ? 'Working…' : 'Test'}
            </button>
            <span className="chrome-spacer" />
            <button type="button" className="btn btn-primary" onClick={saveConfig} disabled={busy}>
              Save settings
            </button>
          </div>

          {testResult && (
            <div className="dropai-reply" role="status">
              <span className="field-label">Reply</span> {testResult}
            </div>
          )}

          <div style={{ borderTop: '1px solid var(--line)', paddingTop: 10, marginTop: 4 }}>
            <div className="popover-title">API key</div>
            <div className="field" style={{ gridTemplateColumns: '92px 1fr' }}>
              <span className="field-label">Status</span>
              <span style={{ color: hasKey ? 'var(--accent)' : 'var(--text-3)' }}>{hasKey ? `Stored · ${protection}` : 'Not set'}</span>
            </div>
            <label className="field" style={{ gridTemplateColumns: '92px 1fr' }}>
              <span className="field-label">{hasKey ? 'Replace' : 'Key'}</span>
              <input className="text-input mono" type="password" value={keyInput} disabled={busy} onChange={(e) => setKeyInput(e.target.value)} placeholder={hasKey ? '•••••••• (leave blank to keep)' : 'sk-… / your key'} spellCheck={false} autoComplete="off" />
            </label>
            <div className="popover-actions">
              {hasKey && (
                <button type="button" className="btn" onClick={clearKey} disabled={busy} style={{ color: 'var(--danger)' }}>
                  Remove key
                </button>
              )}
              <span className="chrome-spacer" />
              <button type="button" className="btn btn-primary" onClick={saveKey} disabled={busy || keyInput.trim().length === 0}>
                Save key
              </button>
            </div>
          </div>
        </>
      )}

      {error && (
        <p className="popover-error" role="alert" style={{ marginTop: 8 }}>
          {error}
        </p>
      )}

      <p className="dropai-disclaimer">
        For authorized security testing and education only. You are responsible for how you use DropSuite, your API key, and
        anything you send to a model. Do not test targets or send data you are not permitted to.
      </p>

      <div className="popover-actions" style={{ marginTop: 12 }}>
        <span className="chrome-spacer" />
        <button type="button" className="btn" onClick={onClose}>
          Close
        </button>
      </div>
    </div>
  );
};

interface ModelPickerProps {
  value: string;
  options: string[];
  onChange: (v: string) => void;
  disabled: boolean;
}

const ModelPicker: React.FC<ModelPickerProps> = ({ value, options, onChange, disabled }) => {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener('mousedown', onDown);
    return () => window.removeEventListener('mousedown', onDown);
  }, [open]);

  const needle = q.trim().toLowerCase();
  const filtered = needle ? options.filter((o) => o.toLowerCase().includes(needle)) : options;

  const pick = (m: string) => {
    onChange(m);
    setOpen(false);
    setQ('');
  };

  return (
    <div className="model-picker" ref={ref}>
      <button type="button" className="text-input mono model-trigger" disabled={disabled} onClick={() => setOpen((o) => !o)}>
        <span className="model-trigger-text">{value || 'Select a model'}</span>
        <ChevronDown size={14} />
      </button>
      {open && (
        <div className="model-list">
          <input className="text-input mono model-search" autoFocus placeholder={`Filter ${options.length} models…`} value={q} onChange={(e) => setQ(e.target.value)} spellCheck={false} />
          <div className="model-options">
            {filtered.map((o) => (
              <button type="button" key={o} className={`model-option${o === value ? ' on' : ''}`} onClick={() => pick(o)}>
                {o}
              </button>
            ))}
            {filtered.length === 0 && needle && (
              <button type="button" className="model-option" onClick={() => pick(q.trim())}>
                Use “{q.trim()}” (custom)
              </button>
            )}
            {filtered.length === 0 && !needle && <div className="model-empty">No models</div>}
          </div>
        </div>
      )}
    </div>
  );
};
