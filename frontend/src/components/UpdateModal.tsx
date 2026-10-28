import React, { useEffect, useState } from 'react';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { DownloadProgress, UpdateInfo } from '../types';
import { DESKTOP, engine } from '../lib/transport';

interface Props {
  update: UpdateInfo;
  onClose: () => void;
  onToast?: (msg: string) => void;
}

export const AUTO_INSTALL_KEY = 'updates.autoInstallWithoutAsking';

export function isAutoInstallEnabled(): boolean {
  try {
    return localStorage.getItem(AUTO_INSTALL_KEY) === 'true';
  } catch {
    return false;
  }
}

export function setAutoInstallEnabled(val: boolean) {
  try {
    localStorage.setItem(AUTO_INSTALL_KEY, val ? 'true' : 'false');
  } catch {
    /* ignore */
  }
}

export const UpdateModal: React.FC<Props> = ({ update, onClose, onToast }) => {
  const [downloading, setDownloading] = useState(false);
  const [progress, setProgress] = useState<number>(0);
  const [downloadedPath, setDownloadedPath] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [restarting, setRestarting] = useState(false);

  const version = update.latest || 'latest';

  // Listen for download progress events emitted from Tauri backend
  useEffect(() => {
    if (!DESKTOP) return;
    let unlisten: (() => void) | undefined;
    try {
      const win = getCurrentWindow();
      win
        .listen<DownloadProgress>('update-download-progress', (event) => {
          if (event.payload && typeof event.payload.percent === 'number') {
            setProgress(Math.round(event.payload.percent));
          }
        })
        .then((u) => {
          unlisten = u;
        })
        .catch(() => {});
    } catch {
      /* ignore */
    }

    return () => {
      unlisten?.();
    };
  }, []);

  // Automatically start download if requested
  const startDownload = async () => {
    setDownloading(true);
    setError(null);
    setProgress(0);
    try {
      const path = await engine.downloadUpdate(version, update.asset_url ?? undefined);
      setDownloadedPath(path);
      setProgress(100);
      setDownloading(false);
    } catch (err) {
      setDownloading(false);
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      onToast?.(`Download failed: ${msg}`);
    }
  };

  useEffect(() => {
    // Automatically trigger download when modal opens
    void startDownload();
  }, []);

  const handleRestart = async () => {
    if (!downloadedPath) return;
    setRestarting(true);
    try {
      await engine.installAndRestart(downloadedPath);
    } catch (err) {
      setRestarting(false);
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      onToast?.(`Failed to restart: ${msg}`);
    }
  };

  const isReady = !!downloadedPath && !downloading;

  return (
    <div className="fz-modal-backdrop update-modal-backdrop" onMouseDown={onClose}>
      <div
        className="update-dialog-card"
        role="dialog"
        aria-label={`DropSuite ${version} is out`}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <h2 className="update-dialog-title">dropsuite {version} is out</h2>

        {!isReady ? (
          <div className="update-dialog-body">
            <p className="update-dialog-notes">
              {update.notes?.trim() ||
                `DropSuite ${version} is now available with new security auditing enhancements, bug fixes, and performance improvements.`}
            </p>

            <p className="update-dialog-subtext">
              You have {update.current}. To install new versions without this question, turn on install
              updates without asking in Settings &gt; About.
            </p>

            {error ? (
              <div className="update-dialog-error">
                <span>{error}</span>
                <button type="button" className="btn btn-sm" onClick={startDownload} style={{ marginTop: '8px' }}>
                  Retry download
                </button>
              </div>
            ) : (
              <div className="update-progress-section">
                <div className="update-progress-bar" role="progressbar" aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100}>
                  <div
                    className="update-progress-fill"
                    style={{ width: `${Math.max(progress, downloading ? 5 : 0)}%` }}
                  />
                </div>
                <div className="update-progress-label">
                  <span>{progress > 0 ? `Downloading... ${progress}%` : 'Downloading...'}</span>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="update-dialog-body">
            <p className="update-dialog-installed">
              DropSuite {version} is installed. It runs once DropSuite restarts.
            </p>

            <div className="update-dialog-actions">
              <button
                type="button"
                className="update-btn-pill update-btn-later"
                onClick={onClose}
                disabled={restarting}
              >
                later
              </button>
              <button
                type="button"
                className="update-btn-pill update-btn-restart"
                onClick={handleRestart}
                disabled={restarting}
              >
                {restarting ? 'restarting...' : 'restart now'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

