import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';
import { installUndoRedo } from './lib/undoRedo';
import { applyTheme, readStoredTheme } from './lib/theme';

// Set the saved theme before the first paint so there is no flash of the wrong one.
applyTheme(readStoredTheme());

// Controlled inputs break the browser's native undo; restore Ctrl+Z / Ctrl+Y app-wide.
installUndoRedo();

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
