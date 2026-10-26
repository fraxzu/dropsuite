import React, { useEffect, useState } from 'react';
import { ArrowUpCircle, X, ExternalLink } from 'lucide-react';
import { DESKTOP, engine } from '../lib/transport';
import { checkOnLaunchEnabled } from './AboutPanel';

const DISMISSED_KEY = 'updates.dismissedVersion';

/** On launch, quietly asks GitHub whether a newer DropSuite is published and, if so, shows a small
 *  corner card with a link to what's new. Respects the "check on launch" setting and remembers a
 *  dismissed version so it does not nag. Any network problem is silent. */
export const UpdatePopup: React.FC = () => {
  const [latest, setLatest] = useState<string | null>(null);

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
        if (u.latest !== dismissed) setLatest(u.latest);
      })
      .catch(() => {
        /* a launch check never disrupts the app */
      });
    return () => {
      live = false;
    };
  }, []);

  if (!latest) return null;

  const dismiss = () => {
    try {
      localStorage.setItem(DISMISSED_KEY, latest);
    } catch {
      /* ignore */
    }
    setLatest(null);
  };

  return (
    <div className="update-popup" role="status">
      <ArrowUpCircle size={16} className="update-popup-icon" aria-hidden="true" />
      <div className="update-popup-text">
        <strong>New version available</strong>
        <span>{latest} is ready on GitHub.</span>
      </div>
      <button className="btn btn-primary" onClick={() => void engine.openReleasePage()}>
        <ExternalLink size={12} /> What's new
      </button>
      <button className="icon-btn" aria-label="Dismiss" onClick={dismiss}>
        <X size={14} />
      </button>
    </div>
  );
};
