import React, { useCallback, useEffect, useState } from 'react';
import { ApplySettings, BrowserPreset, CookieRow } from '../types';
import { engine } from '../lib/transport';

interface Props {
  onToast?: (msg: string) => void;
}

const PRESETS: { value: BrowserPreset; label: string }[] = [
  { value: 'off', label: 'Off - send only what is typed' },
  { value: 'chrome', label: 'Chrome' },
  { value: 'edge', label: 'Edge' },
  { value: 'firefox', label: 'Firefox' },
  { value: 'safari', label: 'Safari' },
];

/**
 * Header preset and cookie jar. Both feed Replay and Fuzzer requests, which is what bot
 * protection scores before letting a request through.
 */
export const CookieJarPanel: React.FC<Props> = ({ onToast }) => {
  const [apply, setApply] = useState<ApplySettings | null>(null);
  const [cookies, setCookies] = useState<CookieRow[]>([]);
  const [available, setAvailable] = useState(true);
  const [host, setHost] = useState('');
  const [raw, setRaw] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [settings, jar] = await Promise.all([engine.getApplySettings(), engine.listCookies()]);
      setApply(settings);
      setCookies(jar);
    } catch {
      setAvailable(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const saveApply = async (next: ApplySettings) => {
    setApply(next);
    try {
      const saved = await engine.setApplySettings(next.preset, next.cookie_jar);
      setApply(saved);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const addCookie = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await engine.saveCookie(host.trim(), raw.trim());
      setRaw('');
      await load();
      onToast?.(`Cookie saved for ${host.trim()}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (row: CookieRow) => {
    try {
      await engine.deleteCookie(row.host, row.name, row.path);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const clearAll = async () => {
    try {
      await engine.clearCookies();
      await load();
      onToast?.('Cookie jar cleared');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  if (!available) {
    return (
      <div className="cookie-jar-section" style={{ borderTop: '1px solid var(--line)', marginTop: 12, paddingTop: 10 }}>
        <div className="field" style={{ marginBottom: 0 }}>
          <span className="field-label">Browser fingerprint</span>
          <span className="field-hint">Available in the desktop app.</span>
        </div>
      </div>
    );
  }

  return (
    <div className="cookie-jar-section" data-cookie-panel style={{ borderTop: '1px solid var(--line)', marginTop: 12, paddingTop: 10 }}>
      <div className="field" style={{ marginBottom: 4 }}>
        <span className="field-label">Browser fingerprint</span>
        <select
          aria-label="Browser header preset"
          value={apply?.preset ?? 'off'}
          onChange={(e) => apply && void saveApply({ ...apply, preset: e.target.value as BrowserPreset })}
        >
          {PRESETS.map((p) => (
            <option key={p.value} value={p.value}>
              {p.label}
            </option>
          ))}
        </select>
      </div>
      <span className="field-hint" style={{ display: 'block', marginBottom: 10 }}>
        Fills only headers you left empty. Typed headers always win.
      </span>

      <label style={{ display: 'flex', gap: 8, alignItems: 'center', margin: '8px 0', fontSize: 'var(--fs-sm)', cursor: 'pointer' }}>
        <input
          type="checkbox"
          checked={apply?.cookie_jar ?? false}
          onChange={(e) => apply && void saveApply({ ...apply, cookie_jar: e.target.checked })}
        />
        <span>Attach jar cookies to Replay and Fuzzer</span>
      </label>

      <form onSubmit={addCookie} style={{ marginTop: 8 }}>
        <input
          className="text-input"
          aria-label="Cookie host"
          placeholder="api.example.com"
          value={host}
          onChange={(e) => setHost(e.target.value)}
          spellCheck={false}
          style={{ width: '100%', boxSizing: 'border-box' }}
        />
        <input
          className="text-input"
          aria-label="Cookie value"
          placeholder="cf_clearance=... (attributes allowed)"
          value={raw}
          onChange={(e) => setRaw(e.target.value)}
          spellCheck={false}
          style={{ width: '100%', boxSizing: 'border-box', marginTop: 6 }}
        />
        <div className="popover-actions" style={{ marginTop: 6, display: 'flex', gap: 8 }}>
          <button type="submit" className="btn btn-sm" disabled={busy || !host.trim() || !raw.trim()}>
            {busy ? 'Saving...' : 'Add cookie'}
          </button>
          <span className="chrome-spacer" />
          <button type="button" className="btn btn-sm" onClick={clearAll} disabled={cookies.length === 0}>
            Clear jar
          </button>
        </div>
      </form>

      {error && <span className="field-hint" style={{ color: 'var(--danger, #f87171)', display: 'block', marginTop: 4 }}>{error}</span>}

      {cookies.length > 0 && (
        <ul style={{ listStyle: 'none', margin: '10px 0 0', padding: 0, maxHeight: 150, overflowY: 'auto', border: '1px solid var(--line)', borderRadius: 'var(--radius)', background: 'var(--ground)' }}>
          {cookies.map((c) => (
            <li key={`${c.host}|${c.name}|${c.path}`} className="cookie-row" style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px', borderBottom: '1px solid var(--line-subtle, rgba(255,255,255,0.05))' }}>
              <span className="mono cookie-name" style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 'var(--fs-xs)' }}>
                <strong>{c.name}</strong>
                <span className="field-hint" style={{ marginLeft: 4 }}>@{c.host}{c.path}</span>
              </span>
              {(c.secure || c.http_only) && (
                <span className="field-hint" style={{ fontSize: '10px', opacity: 0.8, whiteSpace: 'nowrap' }}>
                  {[c.secure ? 'Secure' : '', c.http_only ? 'HttpOnly' : ''].filter(Boolean).join(' ')}
                </span>
              )}
              <button
                type="button"
                className="btn btn-xs"
                onClick={() => void remove(c)}
                aria-label={`Delete ${c.name}`}
                style={{ padding: '1px 6px', fontSize: '11px', lineHeight: 1 }}
              >
                x
              </button>
            </li>
          ))}
        </ul>
      )}
      {cookies.length === 0 && <span className="field-hint" style={{ display: 'block', marginTop: 8 }}>Jar is empty.</span>}
    </div>
  );
};
