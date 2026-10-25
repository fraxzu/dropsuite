import React from 'react';
import { X } from 'lucide-react';

interface Props {
  onClose: () => void;
}

interface Section {
  title: string;
  steps: React.ReactNode[];
}

const SECTIONS: Section[] = [
  {
    title: 'Quick start',
    steps: [
      <>Press <strong>Start</strong> (top bar) to run the local proxy listener on 127.0.0.1:8080.</>,
      <>Open <strong>Listener</strong> settings to generate the root CA and, for HTTPS, add the hosts you want decrypted to the allowlist. Trust the CA only while you test.</>,
      <>Point a browser at the proxy (or use the built-in browser button in Proxy), then browse your target.</>,
    ],
  },
  {
    title: 'Proxy',
    steps: [
      <>Shows <strong>HTTP history</strong>: every request/response that passes through, with method, host, path, status, size and time. Click a row to inspect it.</>,
      <>Only allowlisted HTTPS hosts are decrypted; others are tunnelled untouched.</>,
      <>Use <strong>Intercept</strong> to hold a request, edit it, then Forward or Drop it.</>,
      <>Send any captured request to <strong>Replay</strong>, export the history as HAR, or click <strong>Analyze with AI</strong> on a selected request to have Drop AI review it.</>,
    ],
  },
  {
    title: 'Target',
    steps: [
      <>A <strong>site map</strong> tree of the hosts and paths you have visited, built from history.</>,
      <>Set <strong>Scope</strong> rules (include/exclude by host, port, path). Scope limits which traffic other tools act on, and can drop out-of-scope requests.</>,
      <><strong>Match &amp; Replace</strong> rewrites requests/responses automatically by rule (e.g. swap a header).</>,
    ],
  },
  {
    title: 'Replay',
    steps: [
      <>Edit one request (method, URL, headers, body) and <strong>Send</strong> it directly to the target. Nothing is sent until you press Send.</>,
      <>Each tab keeps its own attempt history; compare two responses side by side.</>,
      <>The response has an <strong>Issues</strong> tab that passively flags security problems (missing/weak headers, information disclosure, insecure cookies, reflected input, error leakage) with severity colours. A red count means a high-severity finding. In that tab, <strong>Triage with AI</strong> rates each finding (true/false positive, priority, fix) and <strong>Draft report</strong> turns them into a ready-to-paste Markdown report.</>,
      <>Click <strong>Analyze with AI</strong> above the response to have Drop AI review the request/response for weaknesses and suggest next steps (configure a model under Drop AI first).</>,
      <>Shortcuts: Ctrl+Enter sends, Ctrl+T new tab, Ctrl+D duplicate, Ctrl+W close.</>,
    ],
  },
  {
    title: 'Fuzzer',
    steps: [
      <>Mark positions in the request by wrapping text in <strong>{'{{ }}'}</strong> (select text, then <strong>Add position</strong>).</>,
      <><strong>Sniper</strong> tries one payload set across each position in turn; <strong>Cluster bomb</strong> tries every combination, one set per position.</>,
      <>Set payloads as a <strong>List</strong> or a <strong>Number range</strong>. Tune concurrency and delay; out-of-scope and restricted targets are refused, not sent.</>,
      <>Load a built-in list from <strong>Presets</strong>, or use the <strong>AI</strong> button to have Drop AI suggest payloads.</>,
      <>Press <strong>Start attack</strong> and watch results stream in. <strong>Click any result row</strong> to open that exact request in a Replay tab and inspect or resend it.</>,
    ],
  },
  {
    title: 'Decoder',
    steps: [
      <>Encode or decode text: Base64, URL, Hex, HTML, plus JWT decode. Everything runs locally; nothing is sent anywhere.</>,
      <>Chain steps with <strong>Use as input</strong> (e.g. URL-decode, then Base64-decode).</>,
    ],
  },
  {
    title: 'Comparer',
    steps: [
      <>Paste two texts (requests, responses, tokens) into A and B to see a line-by-line <strong>diff</strong>: changed, removed and added lines.</>,
    ],
  },
  {
    title: 'Scanner (passive)',
    steps: [
      <>Reads the captured HTTP history and runs the same passive checks across <strong>all</strong> traffic, then groups the findings by type and severity. It only reads; it sends no requests.</>,
      <>Browse your target through the proxy first (so there is traffic to scan), then open <strong>Scanner</strong>. It scans automatically; use <strong>Rescan</strong> after more browsing.</>,
      <>Each row shows severity, how many requests it affects, and the hosts. Expand <strong>Affected requests</strong> to see them. Use <strong>Triage with AI</strong> and <strong>Draft report</strong> on the whole scan.</>,
    ],
  },
  {
    title: 'Drop AI (bring your own key)',
    steps: [
      <>Open the <strong>Drop AI</strong> button in the top bar. Pick a provider (OpenAI-compatible or Anthropic-compatible), set the base URL, and save your API key. The key is stored protected at rest and never logged.</>,
      <>Click <strong>Detect</strong> to list the models your endpoint exposes, then pick one. <strong>Test</strong> sends a tiny request to confirm it works.</>,
      <><strong>Temperature</strong> controls randomness (0 is focused); <strong>Max tokens</strong> caps the reply length. Reasoning models may need a higher Max tokens.</>,
      <>Calls go straight to your endpoint, never through the proxy. Every send is explicit, previews what will be sent, and redacts secrets by default.</>,
      <><strong>Warning:</strong> routing provider models (Claude, GPT, Codex, Gemini) through third-party endpoints can break their terms and risk account bans. Use only models you are allowed to access that way.</>,
    ],
  },
];

export const HelpGuide: React.FC<Props> = ({ onClose }) => {
  return (
    <div className="fz-modal-backdrop" data-tauri-drag-region="false" onMouseDown={onClose}>
      <div className="fz-modal guide-modal" role="dialog" aria-label="DropSuite guide" onMouseDown={(e) => e.stopPropagation()}>
        <div className="fz-modal-head">
          <span className="fz-title">How to use DropSuite</span>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <X size={14} />
          </button>
        </div>

        <p className="guide-disclaimer">
          DropSuite is a web security testing toolkit for <strong>authorized testing and education only</strong>. Only test
          systems you own or have written permission to test. You are responsible for how you use it.
        </p>

        <div className="guide-body">
          {SECTIONS.map((s) => (
            <section className="guide-section" key={s.title}>
              <h3>{s.title}</h3>
              <ul>
                {s.steps.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ul>
            </section>
          ))}
        </div>

        <div className="fz-actions" style={{ justifyContent: 'flex-end' }}>
          <button className="btn btn-primary" onClick={onClose}>
            Got it
          </button>
        </div>
      </div>
    </div>
  );
};
