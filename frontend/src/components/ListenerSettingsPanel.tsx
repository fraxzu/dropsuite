import React, { useEffect, useRef, useState } from 'react';
import { HttpsSettings, ListenerSettings } from '../types';
import { engine } from '../lib/transport';
import { CookieJarPanel } from './CookieJarPanel';

interface Props {
  running: boolean;
  onClose: () => void;
  onSaved: (port: number) => void;
  onToast?: (msg: string) => void;
}

export const ListenerSettingsPanel: React.FC<Props> = ({ running, onClose, onSaved, onToast }) => {
  const [settings, setSettings] = useState<ListenerSettings | null>(null);
  const [https, setHttps] = useState<HttpsSettings | null>(null);
  const [portValue, setPortValue] = useState('');
  const [allowlistText, setAllowlistText] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [saving, setSaving] = useState(false);
  const [savingAllowlist, setSavingAllowlist] = useState(false);
  const [allowlistSaved, setAllowlistSaved] = useState(false);
  const [allowlistMsg, setAllowlistMsg] = useState<string | null>(null);
  const [caWorking, setCaWorking] = useState(false);
  const [showTrustGuide, setShowTrustGuide] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    engine
      .listenerSettings()
      .then((s) => {
        setSettings(s);
        setPortValue(String(s.port));
        requestAnimationFrame(() => input.current?.select());
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));

    engine
      .httpsSettings()
      .then((h) => {
        setHttps(h);
        setAllowlistText(h.allowlist.join(', '));
      })
      .catch(() => {
        // Dev bridge or desktop error
      });
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
      }
    };
    const onDown = (e: MouseEvent) => {
      if (
        root.current &&
        !root.current.contains(e.target as Node) &&
        !(e.target as Element).closest?.('[data-settings-toggle]')
      )
        onClose();
    };
    window.addEventListener('keydown', onKey, true);
    window.addEventListener('mousedown', onDown);
    return () => {
      window.removeEventListener('keydown', onKey, true);
      window.removeEventListener('mousedown', onDown);
    };
  }, [onClose]);

  const savePort = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!settings) return;
    const port = Number(portValue.trim());
    if (!/^\d+$/.test(portValue.trim()) || port < settings.min_port || port > settings.max_port) {
      setError(`Choose a port from ${settings.min_port} to ${settings.max_port}.`);
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const next = await engine.setListenerPort(port);
      setSettings(next);
      onSaved(next.port);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  };

  const saveAllowlist = async () => {
    const entries = allowlistText
      .split(/[,\n]/)
      .map((s) => s.trim())
      .filter(Boolean);
    setSavingAllowlist(true);
    setError(null);
    try {
      const updated = await engine.setHttpsAllowlist(entries);
      setHttps(updated);
      setAllowlistText(updated.allowlist.join(', '));
      setAllowlistSaved(true);
      const msg =
        updated.allowlist.length > 0
          ? `Allowlist saved: ${updated.allowlist.length} host(s) (${updated.allowlist.join(', ')})`
          : 'Allowlist cleared';
      setAllowlistMsg(msg);
      onToast?.(msg);
      setTimeout(() => {
        setAllowlistSaved(false);
        setAllowlistMsg(null);
      }, 3000);
    } catch (err) {
      const errStr = err instanceof Error ? err.message : String(err);
      setError(errStr);
      onToast?.(`Failed to save allowlist: ${errStr}`);
    } finally {
      setSavingAllowlist(false);
    }
  };

  const handleGenerateCa = async () => {
    setCaWorking(true);
    setError(null);
    try {
      const updated = await engine.generateCaCertificate();
      setHttps(updated);
      onToast?.('Root CA certificate generated successfully');
    } catch (err) {
      const errStr = err instanceof Error ? err.message : String(err);
      setError(errStr);
      onToast?.(`Failed to generate CA: ${errStr}`);
    } finally {
      setCaWorking(false);
    }
  };

  const handleRemoveCa = async () => {
    setCaWorking(true);
    setError(null);
    try {
      const updated = await engine.removeCaCertificate();
      setHttps(updated);
      onToast?.('Root CA certificate removed');
    } catch (err) {
      const errStr = err instanceof Error ? err.message : String(err);
      setError(errStr);
      onToast?.(`Failed to remove CA: ${errStr}`);
    } finally {
      setCaWorking(false);
    }
  };

  const handleCopyPem = async () => {
    try {
      const pem = await engine.exportCaCertificate();
      await navigator.clipboard.writeText(pem);
      setCopied(true);
      onToast?.('CA certificate PEM copied to clipboard');
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      const errStr = err instanceof Error ? err.message : String(err);
      setError(errStr);
      onToast?.(`Failed to copy PEM: ${errStr}`);
    }
  };

  const locked = running || !settings;
  return (
    <div
      ref={root}
      className="popover listener-settings"
      role="dialog"
      aria-label="Listener settings"
      data-tauri-drag-region="false"
      style={{ width: 380, maxHeight: '85vh', overflowY: 'auto' }}
    >
      <form onSubmit={savePort}>
        <div className="popover-title">Proxy Listener</div>
        <div className="field">
          <span className="field-label">Address</span>
          <span className="mono">{settings?.bind_address ?? '127.0.0.1'}</span>
          <span className="field-hint">Loopback only</span>
        </div>
        <label className="field">
          <span className="field-label">Port</span>
          <input
            ref={input}
            className="text-input mono"
            inputMode="numeric"
            value={portValue}
            disabled={locked}
            aria-invalid={!!error}
            aria-describedby="port-hint"
            onChange={(e) => {
              setPortValue(e.target.value);
              setError(null);
            }}
          />
          <span className="field-hint" id="port-hint">
            {settings ? `Default ${settings.default_port} · ${settings.min_port}–${settings.max_port}` : ''}
          </span>
        </label>
        {running && <p className="popover-note">Stop the listener to change its port.</p>}
        {settings?.port_from_env && (
          <p className="popover-note">
            This launch pins the port with DROPSUITE_PROXY_PORT. A saved port applies to normal launches.
          </p>
        )}
        <div className="popover-actions" style={{ marginBottom: 12 }}>
          <button
            type="button"
            className="btn"
            disabled={locked || saving}
            onClick={() => {
              setPortValue(String(settings?.default_port ?? 8080));
              setError(null);
            }}
          >
            Use default
          </button>
          <span className="chrome-spacer" />
          <button type="submit" className="btn btn-primary" disabled={locked || saving}>
            {saving ? 'Saving...' : 'Save Port'}
          </button>
        </div>

        {/* --- HTTPS & Root CA Section --- */}
        <div style={{ borderTop: '1px solid var(--line)', paddingTop: 10, marginTop: 10 }}>
          <div className="popover-title">HTTPS Interception & CA</div>

          <div className="field">
            <span className="field-label">CA Status</span>
            <span style={{ color: https?.ca_present ? 'var(--accent)' : 'var(--text-3)' }}>
              {https?.ca_present ? 'Active (Root CA present)' : 'Not generated'}
            </span>
            <span className="field-hint">
              Key: {https?.key_protection ?? 'Windows DPAPI (current user)'}
            </span>
          </div>

          {https?.ca_present && https.fingerprint && (
            <div className="field">
              <span className="field-label">SHA-256</span>
              <span className="mono selectable" style={{ fontSize: '10px', wordBreak: 'break-all' }}>
                {https.fingerprint}
              </span>
            </div>
          )}

          <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
            {https?.ca_present ? (
              <>
                <button
                  type="button"
                  className="btn"
                  onClick={handleCopyPem}
                  disabled={caWorking}
                >
                  {copied ? 'Copied PEM!' : 'Export Public CA (.pem)'}
                </button>
                <button
                  type="button"
                  className="btn"
                  onClick={handleRemoveCa}
                  disabled={caWorking}
                  style={{ color: 'var(--danger)' }}
                >
                  Remove CA
                </button>
              </>
            ) : (
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleGenerateCa}
                disabled={caWorking}
              >
                {caWorking ? 'Generating...' : 'Generate Root CA'}
              </button>
            )}
            <button
              type="button"
              className="btn"
              onClick={() => setShowTrustGuide((g) => !g)}
              style={{ fontSize: '11px' }}
            >
              {showTrustGuide ? 'Hide Guide' : 'Trust Setup'}
            </button>
          </div>

          {showTrustGuide && (
            <div
              style={{
                background: 'var(--ground)',
                padding: '8px 10px',
                borderRadius: 'var(--radius)',
                fontSize: '11px',
                color: 'var(--text-2)',
                marginBottom: 10,
                border: '1px solid var(--line)',
              }}
            >
              <p style={{ margin: '0 0 6px 0', fontWeight: 600 }}>
                Trusting this CA allows DropSuite to impersonate allowlisted HTTPS hosts while the proxy is running.
              </p>
              <p style={{ margin: '0 0 4px 0' }}>
                <strong>Windows (Edge/Chrome):</strong> Run in PowerShell:
              </p>
              <pre
                className="mono selectable"
                style={{
                  background: 'var(--panel)',
                  padding: '4px 6px',
                  borderRadius: 3,
                  margin: '0 0 6px 0',
                  overflowX: 'auto',
                }}
              >
                certutil -user -addstore Root root-ca.pem
              </pre>
              <p style={{ margin: '0 0 4px 0' }}>
                <strong>Firefox:</strong> Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import → select exported root-ca.pem → check &quot;Trust this CA to identify websites&quot;.
              </p>
              <p style={{ margin: '0', color: 'var(--text-3)' }}>
                To revoke: remove the certificate from your user store, or click Remove CA above.
              </p>
            </div>
          )}

          {/* Allowlist Field */}
          <label className="field" style={{ gridTemplateColumns: '80px 1fr' }}>
            <span className="field-label">Allowlist</span>
            <input
              className="text-input mono"
              placeholder="localhost, 127.0.0.1, lumens.my.id:443"
              value={allowlistText}
              onChange={(e) => setAllowlistText(e.target.value)}
              onBlur={saveAllowlist}
            />
            <span className="field-hint" style={{ gridColumn: 2 }}>
              Only these HTTPS hosts are decrypted. Others are tunneled without decryption.
            </span>
          </label>
        </div>

        {allowlistMsg && (
          <div
            role="status"
            style={{
              marginTop: 10,
              fontSize: '11px',
              color: 'var(--accent)',
              background: 'rgba(56, 189, 248, 0.1)',
              padding: '6px 10px',
              borderRadius: 4,
              border: '1px solid rgba(56, 189, 248, 0.25)',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <span>✓</span> {allowlistMsg}
          </div>
        )}

        {error && (
          <p className="popover-error" role="alert" style={{ marginTop: 8 }}>
            {error}
          </p>
        )}

        <div className="popover-actions" style={{ marginTop: 12 }}>
          <button
            type="button"
            className={`btn ${allowlistSaved ? 'btn-primary' : ''}`}
            onClick={saveAllowlist}
            disabled={savingAllowlist}
            style={
              allowlistSaved
                ? { background: 'var(--accent)', color: '#000', fontWeight: 600 }
                : undefined
            }
          >
            {savingAllowlist ? 'Saving...' : allowlistSaved ? '✓ Saved!' : 'Save Allowlist'}
          </button>
          <span className="chrome-spacer" />
          <button type="button" className="btn" onClick={onClose}>
            Close
          </button>
        </div>

        <CookieJarPanel onToast={onToast} />

        {settings?.log_dir && (
          <p className="popover-foot">
            Diagnostic log (local only): <span className="mono selectable">{settings.log_dir}</span>
          </p>
        )}
      </form>
    </div>
  );
};
