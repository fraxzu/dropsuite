import React, { useEffect, useState } from 'react';
import { X, FolderOpen, Loader2, RefreshCw, ExternalLink } from 'lucide-react';
import { engine } from '../lib/transport';
import { AppInfo, UpdateInfo } from '../types';
import { useStoredState } from '../lib/useStoredState';
import { applyTheme, DEFAULT_THEME, THEME_KEY, THEMES, ThemeId } from '../lib/theme';

interface Props {
  onClose: () => void;
  onToast?: (msg: string) => void;
}

const CHECK_ON_LAUNCH_KEY = 'updates.checkOnLaunch';

/** Read the "check on launch" preference (defaults to on). */
export function checkOnLaunchEnabled(): boolean {
  try {
    return localStorage.getItem(CHECK_ON_LAUNCH_KEY) !== 'off';
  } catch {
    return true;
  }
}

/** A small on/off switch matching the app's dark theme. */
const Toggle: React.FC<{ on: boolean; disabled?: boolean; onChange: (v: boolean) => void; label: string }> = ({ on, disabled, onChange, label }) => (
  <button
    type="button"
    role="switch"
    aria-checked={on}
    aria-label={label}
    className={`about-switch${on ? ' on' : ''}`}
    disabled={disabled}
    onClick={() => onChange(!on)}
  >
    <span className="about-switch-knob" />
  </button>
);

/** App settings and about: version, updates, startup, and the local log and data folders.
 *  Adapted for a local-first security tool — everything stays on this machine. */
export const AboutPanel: React.FC<Props> = ({ onClose, onToast }) => {
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [startup, setStartup] = useState<boolean | null>(null);
  const [checkOnLaunch, setCheckOnLaunch] = useState<boolean>(checkOnLaunchEnabled());
  const [update, setUpdate] = useState<UpdateInfo | null>(null);
  const [checking, setChecking] = useState(false);
  const [theme, setTheme] = useStoredState<ThemeId>(THEME_KEY, DEFAULT_THEME);

  // Keep <html data-theme> in step with the stored choice (also covers storage set elsewhere).
  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  useEffect(() => {
    let live = true;
    engine.appInfo().then((i) => live && setInfo(i)).catch((e) => live && setError(e instanceof Error ? e.message : String(e)));
    engine.getStartAtLogin().then((v) => live && setStartup(v)).catch(() => live && setStartup(false));
    return () => {
      live = false;
    };
  }, []);

  const openFolder = async (which: 'data' | 'logs') => {
    try {
      await engine.openAppFolder(which);
    } catch (e) {
      onToast?.(`Could not open the ${which} folder: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const toggleStartup = async (v: boolean) => {
    const prev = startup;
    setStartup(v);
    try {
      await engine.setStartAtLogin(v);
      onToast?.(v ? 'DropSuite will start when you sign in.' : 'DropSuite will no longer start at sign-in.');
    } catch (e) {
      setStartup(prev);
      onToast?.(`Could not change the startup setting: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const toggleCheckOnLaunch = (v: boolean) => {
    setCheckOnLaunch(v);
    try {
      localStorage.setItem(CHECK_ON_LAUNCH_KEY, v ? 'on' : 'off');
    } catch {
      /* ignore */
    }
  };

  const checkNow = async () => {
    setChecking(true);
    try {
      const u = await engine.checkForUpdate();
      setUpdate(u);
    } catch (e) {
      onToast?.(`Update check failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setChecking(false);
    }
  };

  const whatsNew = async () => {
    try {
      await engine.openReleasePage();
    } catch (e) {
      onToast?.(`Could not open the releases page: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  return (
    <div className="fz-modal-backdrop" onMouseDown={onClose}>
      <div className="fz-modal about-modal" role="dialog" aria-label="Settings and about" onMouseDown={(e) => e.stopPropagation()}>
        <div className="fz-modal-head">
          <span className="fz-title">Settings &amp; about</span>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <X size={14} />
          </button>
        </div>

        <div className="about-body">
          <section className="about-section">
            <h3>Appearance</h3>
            <div className="theme-picker" role="radiogroup" aria-label="Theme">
              {THEMES.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  role="radio"
                  aria-checked={theme === t.id}
                  className={`theme-option${theme === t.id ? ' on' : ''}`}
                  onClick={() => setTheme(t.id)}
                >
                  <span className={`theme-swatch theme-swatch-${t.id}`} aria-hidden="true" />
                  <span className="theme-option-label">{t.label}</span>
                </button>
              ))}
            </div>
            <p className="fz-hint">{THEMES.find((t) => t.id === theme)?.hint}</p>
          </section>

          <section className="about-section">
            <h3>Version</h3>
            {info ? (
              <p className="mono">DropSuite {info.version} · {info.os} {info.arch} · installed with the setup</p>
            ) : error ? (
              <p className="fz-issue">{error}</p>
            ) : (
              <p className="fz-hint"><Loader2 size={12} className="spin" /> Reading…</p>
            )}
          </section>

          <section className="about-section">
            <h3>Updates</h3>
            <div className="about-row">
              <div className="about-row-text">
                <strong>Check when DropSuite starts</strong>
                <span className="fz-hint">On launch, ask GitHub if a newer version is published. Only the version is checked — no data about you is sent.</span>
              </div>
              <Toggle on={checkOnLaunch} onChange={toggleCheckOnLaunch} label="Check for updates on launch" />
            </div>

            {update && (
              <p className={update.newer ? 'fz-issue' : 'fz-hint'}>
                {update.newer
                  ? `A newer version is available: ${update.latest}. You have ${update.current}.`
                  : update.checked
                    ? `You are on the latest version (${update.current}).`
                    : update.message}
              </p>
            )}

            <div className="about-actions">
              <button className="btn" onClick={checkNow} disabled={checking}>
                {checking ? <Loader2 size={13} className="spin" /> : <RefreshCw size={13} />} Check for updates
              </button>
              <button className="btn" onClick={whatsNew}>
                <ExternalLink size={13} /> What's new (GitHub)
              </button>
            </div>
            <p className="fz-hint">
              A new version opens on GitHub to download. Fully automatic install arrives once signed
              releases are set up.
            </p>
          </section>

          <section className="about-section">
            <h3>Startup</h3>
            <div className="about-row">
              <div className="about-row-text">
                <strong>Start DropSuite when I sign in</strong>
                <span className="fz-hint">The app opens automatically after you log in to Windows.</span>
              </div>
              <Toggle on={!!startup} disabled={startup === null} onChange={toggleStartup} label="Start at login" />
            </div>
          </section>

          <section className="about-section">
            <h3>Logs</h3>
            <p className="fz-hint">
              DropSuite keeps a local log of startup, listener changes and errors (host and port
              only — never captured traffic, headers or bodies). It rotates at about 3 MB and is
              never sent anywhere. Open it here if you need to report a problem.
            </p>
            {info && <p className="mono about-path">{info.logs_dir}</p>}
            <button className="btn" onClick={() => openFolder('logs')} disabled={!info}>
              <FolderOpen size={13} /> Open logs folder
            </button>
          </section>

          <section className="about-section">
            <h3>Data</h3>
            <p className="fz-hint">
              Everything — captured history, the cookie jar, your root CA and settings — lives in
              this one folder on your machine. Nothing leaves it unless you send it.
            </p>
            {info && <p className="mono about-path">{info.data_dir}</p>}
            <button className="btn" onClick={() => openFolder('data')} disabled={!info}>
              <FolderOpen size={13} /> Open data folder
            </button>
          </section>
        </div>

        <div className="fz-actions" style={{ justifyContent: 'flex-end' }}>
          <button className="btn btn-primary" onClick={onClose}>
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
