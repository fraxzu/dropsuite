import React, { useEffect, useState } from 'react';
import { X, FolderOpen, Loader2 } from 'lucide-react';
import { engine } from '../lib/transport';
import { AppInfo } from '../types';

interface Props {
  onClose: () => void;
  onToast?: (msg: string) => void;
}

/** App settings and about: version, update status, log and data folders. Adapted for a local-first
 *  security tool — everything stays on this machine and nothing is sent anywhere. */
export const AboutPanel: React.FC<Props> = ({ onClose, onToast }) => {
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    engine
      .appInfo()
      .then((i) => live && setInfo(i))
      .catch((e) => live && setError(e instanceof Error ? e.message : String(e)));
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
            <h3>Version</h3>
            {info ? (
              <p className="mono">
                DropSuite {info.version} · {info.os} {info.arch} · installed with the setup
              </p>
            ) : error ? (
              <p className="fz-issue">{error}</p>
            ) : (
              <p className="fz-hint"><Loader2 size={12} className="spin" /> Reading…</p>
            )}
          </section>

          <section className="about-section">
            <h3>Updates</h3>
            <p className="fz-hint">
              This build was installed manually. Automatic update checks arrive once releases are
              published on GitHub; until then, install a newer setup over this one.
            </p>
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
