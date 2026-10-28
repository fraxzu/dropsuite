import React, { useEffect, useState } from 'react';
import { ArrowUpCircle, X, Download } from 'lucide-react';
import { DESKTOP, engine } from '../lib/transport';
import { checkOnLaunchEnabled } from './AboutPanel';
import { UpdateInfo } from '../types';
import { UpdateModal, isAutoInstallEnabled } from './UpdateModal';

const DISMISSED_KEY = 'updates.dismissedVersion';

interface Props {
  onToast?: (msg: string) => void;
}

/** On launch, quietly asks GitHub whether a newer DropSuite is published and, if so, shows a small
 *  corner card with a link to what's new. Respects the "check on launch" setting and remembers a
 *  dismissed version so it does not nag. Any network problem is silent. */
export const UpdatePopup: React.FC<Props> = ({ onToast }) => {
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null);
  const [showModal, setShowModal] = useState<boolean>(false);

  useEffect(() => {
    if (!DESKTOP || !checkOnLaunchEnabled()) return;
    let live = true;
    engine
      .checkForUpdate()
      .then((u) => {
        if (!live || !u.newer || !u.latest) return;
        let dismissed = '';
        try {
          dismissed = localStorage.getItem(DISMISSED_KEY) ?? '';
        } catch {
          /* ignore */
        }
        if (u.latest !== dismissed) {
          setUpdateInfo(u);
          if (isAutoInstallEnabled()) {
            setShowModal(true);
          }
        }
      })
      .catch(() => {
        /* a launch check never disrupts the app */
      });
    return () => {
      live = false;
    };
  }, []);

  if (!updateInfo) return null;

  const dismiss = () => {
    try {
      if (updateInfo.latest) {
        localStorage.setItem(DISMISSED_KEY, updateInfo.latest);
      }
    } catch {
      /* ignore */
    }
    setUpdateInfo(null);
  };

  return (
    <>
      {!showModal && (
        <div className="update-popup" role="status">
          <ArrowUpCircle size={16} className="update-popup-icon" aria-hidden="true" />
          <div className="update-popup-text">
            <strong>New version available</strong>
            <span>{updateInfo.latest} is ready.</span>
          </div>
          <button className="btn btn-primary" onClick={() => setShowModal(true)}>
            <Download size={13} /> Update
          </button>
          <button className="icon-btn" aria-label="Dismiss" onClick={dismiss}>
            <X size={14} />
          </button>
        </div>
      )}

      {showModal && (
        <UpdateModal
          update={updateInfo}
          onClose={() => setShowModal(false)}
          onToast={onToast}
        />
      )}
    </>
  );
};
