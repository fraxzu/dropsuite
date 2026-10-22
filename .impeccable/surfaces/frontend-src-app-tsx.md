---
version: 1
slug: "frontend-src-app-tsx"
primary_target: "frontend/src/App.tsx"
related_targets: []
---

# Surface: DropSuite desktop workspace (Proxy + Target)

Mode: Operate. Audience: solo bug bounty hunter, hours-long sessions on a Windows desktop, keyboard-heavy. Task: watch captured traffic, find the interesting request, read it exactly as it went over the wire, copy evidence out. Constraints: frontend only; Rust API contract on 127.0.0.1:8081 unchanged; no mock traffic; no remote calls (fonts are local system faces); captured HTML/scripts never execute; credentials never re-exposed by the UI. Replay / Fuzzer / Scanner shown as planned, never as working.

Direction source: pinned by the user brief (premium dark, neutral charcoal, restrained electric blue, IDE density; functional references Burp workflow, Proxyman inspector, VS Code panels, Linear type). Pinned direction beats the roll; concept-seed not run.

## Direction contract

THESIS: Traffic is one continuous capture surface, a dense history grid flowing into a split request/response inspector, read top to bottom like an editor, never a dashboard. Refuses the admin arrangement: logo sidebar with metric cards, colored method pills, slide-in detail drawer.

OWN-WORLD: Neutral charcoal in four close steps (chrome darkest, grid, panel header, hover), 1px graphite dividers, no shadows except overlays. One electric blue for selection, focus and the primary action only. Status hues (green, teal, amber, red) appear only as small status text and timeline ticks. Segoe UI Variable for interface, Cascadia Mono strictly for wire data. 24px grid rows, 32px toolbars.

STORY: The hunter sees the listener is live, sees traffic arrive and its rhythm, narrows by text, method, status or time window, selects with j/k, and reads request and response side by side with redactions labelled.

FIRST VIEWPORT: 36px chrome bar (mark, workspace tabs, listener state and Start/Stop at right); 32px filter toolbar; 34px capture timeline; history grid filling about 55%; draggable seam; inspector below split Request | Response, each with Raw / Headers / Body / Params / Hex; 22px status bar.

FORM: Desktop IDE shell (pinned). Signature move: the capture timeline, session rhythm drawn as status-colored ticks with idle gaps collapsed into break marks; drag to scope the grid to a burst, click to select. Seed key: none. The concept roll (concept-seed) was deliberately skipped because the user brief pinned the direction; the user was told so at finish.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
