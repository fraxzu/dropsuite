---
name: DropSuite
description: Local-first intercepting proxy workspace for bug bounty hunters; a dense dark IDE shell, never a dashboard.
colors:
  chrome: "#131417"
  ground: "#18191c"
  panel: "#1c1d21"
  raised: "#222328"
  hover: "#26282d"
  line: "#2a2c31"
  line-strong: "#383a41"
  text: "#e6e7ea"
  text-2: "#a8abb2"
  text-3: "#878a92"
  text-disabled: "#5c5f66"
  accent: "#3d8bff"
  accent-strong: "#2a6fe0"
  accent-text: "#79acff"
  focus: "#4c94ff"
  sel: "#1f3c6b"
  sel-idle: "#1e2a3e"
  status-1xx: "#a8abb2"
  status-2xx: "#4cc38a"
  status-3xx: "#4fbfd4"
  status-4xx: "#e8a43c"
  status-5xx: "#f06a5f"
  danger: "#f06a5f"
  redacted: "#e8a43c"
  syn-key: "#9fc1ff"
  syn-str: "#d4c18e"
  syn-num: "#7fd1c4"
  syn-lit: "#e3a07a"
  syn-punct: "#878a92"
typography:
  display:
    fontFamily: "'Segoe UI Variable Display', 'Segoe UI Variable', 'Segoe UI', system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 600
    lineHeight: 1.4
  brand:
    fontFamily: "'Segoe UI Variable Display', 'Segoe UI Variable', 'Segoe UI', system-ui, sans-serif"
    fontSize: "13px"
    fontWeight: 600
    letterSpacing: "-0.01em"
  body:
    fontFamily: "'Segoe UI Variable Text', 'Segoe UI Variable', 'Segoe UI', system-ui, -apple-system, 'Helvetica Neue', sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.4
  title:
    fontFamily: "'Segoe UI Variable Text', 'Segoe UI Variable', 'Segoe UI', system-ui, sans-serif"
    fontSize: "12px"
    fontWeight: 600
  label:
    fontFamily: "'Segoe UI Variable Text', 'Segoe UI Variable', 'Segoe UI', system-ui, sans-serif"
    fontSize: "11px"
    fontWeight: 600
  meta:
    fontFamily: "'Segoe UI Variable Text', 'Segoe UI Variable', 'Segoe UI', system-ui, sans-serif"
    fontSize: "11px"
    fontWeight: 400
    fontFeature: "tnum"
  wire:
    fontFamily: "'Cascadia Mono', 'Cascadia Code', Consolas, ui-monospace, 'SF Mono', Menlo, monospace"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: "18px"
  wire-strong:
    fontFamily: "'Cascadia Mono', 'Cascadia Code', Consolas, ui-monospace, 'SF Mono', Menlo, monospace"
    fontSize: "11px"
    fontWeight: 600
rounded:
  hair: "2px"
  xs: "3px"
  sm: "4px"
spacing:
  "2": "2px"
  "4": "4px"
  "8": "8px"
  "12": "12px"
  "16": "16px"
  "24": "24px"
  row: "24px"
  bar: "32px"
components:
  button:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.text}"
    typography: "{typography.title}"
    rounded: "{rounded.sm}"
    padding: "0 10px"
    height: "24px"
  button-hover:
    backgroundColor: "{colors.hover}"
  button-disabled:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.text-disabled}"
  button-primary:
    backgroundColor: "{colors.accent-strong}"
    textColor: "#ffffff"
    rounded: "{rounded.sm}"
    padding: "0 10px"
    height: "24px"
  icon-button:
    textColor: "{colors.text-2}"
    rounded: "{rounded.sm}"
    size: "24px"
  icon-button-pressed:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.accent-text}"
  input-search:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.text}"
    typography: "{typography.wire}"
    rounded: "{rounded.sm}"
    padding: "0 30px 0 28px"
    height: "24px"
  select:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.text}"
    rounded: "{rounded.sm}"
    padding: "0 24px 0 8px"
    height: "24px"
  chip-scope:
    backgroundColor: "{colors.sel}"
    textColor: "{colors.text}"
    rounded: "{rounded.sm}"
    padding: "0 4px 0 8px"
    height: "22px"
  workspace-tab:
    textColor: "{colors.text-2}"
    typography: "{typography.body}"
    padding: "0 12px"
  workspace-tab-active:
    textColor: "{colors.text}"
  workspace-tab-planned:
    textColor: "{colors.text-disabled}"
  grid-row:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.text}"
    height: "{spacing.row}"
    padding: "0 8px"
  grid-row-hover:
    backgroundColor: "{colors.hover}"
  grid-row-selected:
    backgroundColor: "{colors.sel}"
  grid-row-selected-idle:
    backgroundColor: "{colors.sel-idle}"
  toolbar:
    backgroundColor: "{colors.panel}"
    height: "{spacing.bar}"
    padding: "0 8px"
  overlay:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.text}"
    rounded: "{rounded.sm}"
    padding: "6px 12px"
---

# Design System: DropSuite

## Overview

**Creative North Star: "The Wire Desk"**

DropSuite is a desktop instrument for reading HTTP exactly as it crossed the wire. Traffic is one continuous capture surface: a dense history grid flowing into a split request/response inspector, read top to bottom like an editor. It is never a dashboard: there is no metric-card grid, no sidebar of big icons, no slide-in drawer, no coloured method pills.

The world is neutral charcoal in close tonal steps, divided by 1px graphite lines, lit by exactly one electric blue that means "you are here, this is focused, this is the action". Everything else that carries colour is information, not decoration: status hues are small text and few-pixel marks, redaction amber flags what the tool changed, syntax tints separate header names from values. Density is IDE density: 24px rows, 32px toolbars, 11 to 13px type, a 36px chrome bar and a 22px status bar framing the work.

The faces are the machine's own. Segoe UI Variable carries the interface and Cascadia Mono carries the wire; nothing is fetched from the network, because the product promises zero remote calls and the type stack is part of keeping that promise.

**Key Characteristics:**
- Four-step charcoal ladder (chrome, ground, panel, raised) plus a hover step; depth by tone, not shadow.
- One electric blue, reserved for selection, focus and the primary action.
- Status hues as text and marks only; never fills, pills or row tints.
- Interface sans for chrome, monospace strictly for wire data and numbers in code views.
- The capture timeline as the signature: session rhythm drawn as status-coloured ticks.
- Evidence first: redactions and transforms are labelled; captured HTML is never rendered.

## Colors

A near-monochrome charcoal field with one electric blue for agency and a small, strictly informational set of status and syntax hues.

### Primary
- **Electric Blue** (accent): the one agency colour. Active workspace-tab underline, active message-tab underline, splitter hover/drag line, sort arrows, timeline scope window (at 14% fill, 55% stroke), caret colour, and the arrival flash on new rows (20%, fading over 1.6s).
- **Pressed Blue** (accent-strong): the primary button fill (Start). Hover lifts to a slightly brighter blue, active sinks darker.
- **Link Blue** (accent-text): text-weight blue for link buttons ("Clear filters") and pressed icon toggles.
- **Focus Blue** (focus): the 2px focus-visible outline and the focused search border.
- **Selection Navy** (sel): the selected grid row, tree item and scope chip while their region has focus.
- **Idle Selection Navy** (sel-idle): the same selection when focus has moved elsewhere, so the selection stays visible but quieter.

### Secondary
- **Status Set** (status-1xx neutral grey, status-2xx green, status-3xx teal, status-4xx amber, status-5xx red): the HTTP status vocabulary. Used as status-code text in the grid and inspector, timeline ticks, 5px site-map status squares, and a 2px inset underline on a pressed status-class filter.
- **Live Green** (status-2xx reused): the 7px listener dot when the proxy is listening. Solid, no halo.
- **Danger Red** (danger): the Stop button's square glyph, the error-state icon, and the error listener dot. Same value as status-5xx.
- **Redaction Amber** (redacted): a named role, not a status. Colours `[REDACTED…]` markers (on a 12% amber wash, 2px radius) and the "N redacted" note in message headers.

### Tertiary
- **Syntax Tints** (syn-key soft blue, syn-str parchment, syn-num sea-glass, syn-lit clay, syn-punct grey): header names and JSON keys, strings, numbers (also path parameters in the site map), literals, punctuation. Low-chroma so wire text stays readable for hours.

### Neutral
- **Chrome** (chrome): darkest step. Chrome bar, status bar, endpoint wells.
- **Ground** (ground): app background, grid body, inspector and code surfaces, inputs.
- **Panel** (panel): toolbars, grid header, inspector header, pane heads, disabled buttons.
- **Raised** (raised): buttons, overlays (tooltip, toast), pressed segments, keycaps.
- **Hover** (hover): row, tree item, header-cell and icon-button hover.
- **Line** (line) and **Strong Line** (line-strong): 1px dividers between regions; strong line for control borders, keycaps and the timeline axis. In-grid row separators use line at 55%.
- **Text ladder** (text, text-2, text-3, text-disabled): primary values and paths; secondary labels and hosts; meta, IDs, placeholders; disabled and line numbers.

### Named Rules
**The One Blue Rule.** Electric blue means selection, focus or the primary action. It never decorates, never marks a category, never tints a status.

**The Status-Is-Ink Rule.** Status hues appear as text and as marks a few pixels across (timeline ticks, 5px squares, a 2px underline, a 7px dot). Never as a pill, a badge fill, a row tint or a background.

**The Amber Means Changed Rule.** Redaction amber marks only what the tool altered (redacted values and the redaction count). Because it shares its value with status-4xx, it always appears as a marker or note, never as a bare status-like number.

## Typography

**Display Font:** Segoe UI Variable Display (with Segoe UI, system-ui)
**Body Font:** Segoe UI Variable Text (with Segoe UI, system-ui, -apple-system, Helvetica Neue)
**Label/Mono Font:** Cascadia Mono (with Cascadia Code, Consolas, ui-monospace, SF Mono, Menlo)

**Character:** A quiet, crisp Windows-native sans for every word the tool says, and a wide, legible coding mono for every byte the target said. The split is semantic: the face tells you whose words you are reading.

### Hierarchy
- **Display** (600, 15px, 1.4): empty- and error-state headings only ("Listener stopped", "No matches").
- **Brand** (Display 600, 14px, -0.015em): the DropSuite wordmark, 9px from the mark.
- **Body** (400, 13px, 1.4; 1.5 in state paragraphs, max ~460px): workspace tabs, state copy, default UI text.
- **Title** (500 to 600, 12px): buttons (500), pane titles and Request / Response titles (600), view tabs (400).
- **Label** (600, 11px): grid column headers, key/value table headers. Sentence case, no tracking, no uppercase.
- **Meta** (400, 11px, tabular figures): toolbar match counts, status bar, notes, inspector facts.
- **Wire** (Cascadia Mono 400, 12px, 18px line): hosts, paths, raw messages, headers, bodies, hex, the search input value, the listener address, breadcrumb and tree paths.
- **Wire Strong** (Cascadia Mono 600, 11px): method and status code cells; the inspector head uses 700 at 12px.

### Named Rules
**The Whose-Words Rule.** Cascadia Mono is for wire data and numbers inside code views (methods, hosts, paths, headers, bodies, hex, addresses, status codes, timeline axis). Interface language is always Segoe UI Variable. Search placeholders switch back to the UI face; typed queries are mono.

**The Local Faces Rule.** Fonts are local system faces only. No webfont, no font CDN, no `@font-face` pointing off the machine. This is a product requirement (zero remote calls), not a style preference.

**The Tabular Numbers Rule.** IDs, lengths, durations, times and counts use tabular figures so columns of numbers align.

## Layout

A fixed desktop IDE shell on a vertical grid: a 36px chrome bar, the workspace, and a 22px status bar (minimum window 960 x 560). The Proxy workspace stacks a 32px filter toolbar, a 34px capture timeline, the history grid (about 55% of the height), a 1px draggable seam, and the inspector split side by side into Request | Response. The Target workspace splits a site-map tree beside the inspector. Split sizes persist.

Rhythm runs on 4px: gaps of 2, 4, 6, 8, 12 and 16px; 8px cell padding; 10 to 12px pane insets; 24px only for empty-state padding. Fixed component heights do the structural work: 24px controls and rows, 22px tree items and chips, 26px grid header, 30px inspector and message heads, 32px toolbars and pane heads.

The history grid is a fixed column grid (ID, Method, Host, Path, Status, Type, Length, Duration, Time) with Path taking the flexible share. Under an 860px container width it drops Type and Time. Rows are virtualized at 24px.

## Elevation & Depth

Flat by construction. Depth is conveyed by the charcoal ladder (chrome darkest at the frame, ground for content, panel for headers, raised for controls) and by 1px lines between regions. Shadows exist only on floating overlays that sit above the work.

### Shadow Vocabulary
- **Tooltip** (`box-shadow: 0 6px 16px rgba(0, 0, 0, 0.45)`): the capture-timeline hover tip.
- **Toast** (`box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5)`): transient confirmations above the status bar.
- **Inset indicator** (`box-shadow: inset 0 -2px 0 <status hue or accent>`): the pressed-segment underline; a line, not a lift.
- **Focus inset** (`box-shadow: inset 0 0 0 1px` focus blue): scroll regions (grid body, tree) that take keyboard focus.

### Named Rules
**The Overlays-Only Shadow Rule.** A surface casts a shadow only if it floats over other content (tooltip, toast). Panes, rows, buttons and headers are flat.

## Shapes

Small, tight corners and hard rectangular regions. Controls, chips, overlays and wells use a 4px radius; keycaps, the "planned" badge and link buttons 3px; redaction markers, skeleton bars and tab underlines 2px. Panes, grid rows and the frame are square. Dividers are 1px lines with a wider invisible hit area on splitters, which light a 3px blue line on hover or drag. Tab indicators are 2px bars at the bottom edge with only the top corners rounded. The listener dot is the only circle.

## Components

### Brand Mark
Two flat slabs on a 30° isometric bias: an upright slab and a folded "7"-shaped slab, separated by an even channel. It is monochrome only and takes the surrounding text colour (`currentColor`): never blue, never outlined, never on a plate inside the UI. In the chrome bar it sits in a 16px box, the size at which its vertical edges land on whole pixels, 9px from the wordmark. Masters, lockups, the favicon and the Windows icon live in `brand/mark/`, with the geometry in `brand/mark/geometry.cjs`. The app icon places the white mark on a charcoal rounded square (#18191c with a 1px #383a41 line).

### Buttons
Neutral, compact, quiet until needed.
- **Shape:** gently squared (4px), 24px tall, 0 10px padding, 12px weight 500.
- **Default:** raised fill, strong-line border, primary text. Hover moves to the hover step with a lighter border; active sinks one step.
- **Primary:** pressed-blue fill and border with white text. Used only for Start, the one primary action in the shell; a future surface gets at most one.
- **Stop:** a default button whose square glyph is danger red; the button itself is not red.
- **Disabled:** panel fill, line border, disabled text.
- **Icon button:** 24px square, text-2 glyph, hover step on hover; pressed toggles show link blue on raised.
- **Link button:** 11px link-blue text, underline on hover.

### Chips
- **Scope chip:** selection-navy fill, 22px, 11px text, an inline 18px clear button. Shows the active time window (for example "08:52:21 – 08:52:32").
- **Planned badge:** 10px disabled text in a 3px-radius strong-line outline, inside disabled workspace tabs.

### Cards / Containers
- **Corner Style:** square panes; 4px only for endpoint wells.
- **Background:** ground for content, panel for headers.
- **Shadow Strategy:** none (see Elevation & Depth).
- **Border:** 1px line between regions.
- **Internal Padding:** 8 to 12px.

### Inputs / Fields
- **Search:** ground fill, strong-line border, 4px radius, 24px tall, leading search glyph and trailing `/` keycap. Typed text is Cascadia Mono 12px; the placeholder is the UI face in text-3.
- **Select and segmented:** same height, fill and border. Segments are mono 11px; pressed segments go raised with a 2px inset underline in the segment's own colour (status hue for status classes, blue by default).
- **Focus:** border turns focus blue (search) or a 2px focus-blue outline (everything else).

### Navigation
- **Workspace tabs:** 13px text-2 labels in the chrome bar; hover lifts to panel; the current tab turns primary text with a 2px blue underline inset 10px from each side. Replay, Fuzzer and Scanner are disabled tabs with a "planned" badge, separated from Proxy and Target by a 1px divider.
- **Message tabs:** in the tabbed inspector layout, the Request / Response switch carries a blue underline on the active side; the Raw / Headers / Body / Params / Hex view tabs carry a text-2 grey underline, so blue stays scarce. Counts sit beside labels in 10.5px text-3.
- **Keyboard:** `j`/`k` move, `/` search, `b` scope to burst, `Esc` clears; the status bar lists them with keycaps.

### History Grid
Monochrome rows where only the data that matters lights up. Methods are mono 11px weight 600; read methods (GET, HEAD, OPTIONS) stay text-2, write methods (POST, PUT, PATCH, DELETE) brighten to primary text at the same weight. DELETE is never red. Paths are primary mono with the query string in text-3; hosts are text-2 mono; status codes are mono 600 in their status hue. Selected rows use selection navy when the grid has focus and idle navy otherwise. New rows flash a 20% blue wash that fades over 1.6s.

### Capture Timeline (signature)
A 34px strip under the toolbar that draws the session's rhythm. Each request is a 2px status-coloured tick; 4xx and 5xx ticks stand 3px taller. Idle stretches over 45 seconds collapse into a double-slash break mark so a long session fits the width. Mono 10px clock labels sit at each end. Dragging (or pressing `b` on a selection) draws a blue scope window and filters the grid to that burst; ticks outside the filter dim to 22%. A small primary-text triangle marks the selected request. Hover shows a mono tooltip.

### Inspector
A 30px head carries method, path, host and facts (status, duration, size, timestamp, ID) plus layout toggles. Request and Response sit side by side, each with Raw / Headers / Body / Params / Hex.
- **Raw is rebuilt, never replayed:** the Raw view is always assembled from the redacted parsed header list; the daemon's stored raw head, which holds clear-text secrets, is never rendered.
- **Redaction is labelled:** redacted values render as amber markers, and the message head shows the "N redacted" count.
- **Transforms are labelled:** decoded or prettified bodies carry a note that Raw and Hex keep the captured bytes; JSON offers Pretty / Original.
- **Captured HTML is never rendered;** markup is shown as source with a note saying so. Only raster images preview, on a 12px checkerboard with a 1px line border and a mono meta line.
- **Code view:** 44px right-aligned line-number gutter in disabled text, Cascadia Mono 12px on 18px lines, wrapped. Hex uses an offset, bytes, ASCII grid.

### Site Map
A mono tree of hosts and path segments at 22px rows: hosts primary weight 600, segments text-2, parameter segments sea-glass, counts in 10.5px UI face, and 5px status squares per node. Selection follows the grid's navy pair.

### Chrome and Status Bars
The chrome bar holds the brand mark, the workspace tabs, and the listener state ("Listening on" plus the mono address, a solid 7px green dot) with Start/Stop. The status bar repeats listener wording, captured count and "Stored locally", then keycap hints and the mono API address, all at 11px text-3.

## Do's and Don'ts

### Do:
- **Do** build every surface from the charcoal ladder (chrome, ground, panel, raised, hover) and separate regions with 1px lines.
- **Do** keep electric blue for selection, focus and the primary action; use the navy pair for selected rows (sel when focused, sel-idle when not).
- **Do** show status as coloured mono text, ticks, or marks a few pixels across.
- **Do** set every byte from the wire (methods, hosts, paths, headers, bodies, hex, addresses, status codes) in Cascadia Mono, and every word of interface language in Segoe UI Variable.
- **Do** use local system faces only; the type stack ships no webfont and makes no remote request.
- **Do** label every change the tool makes to evidence: amber for redactions, a plain note for decoding or prettifying.
- **Do** rebuild the Raw view from the redacted parsed header list.
- **Do** show unshipped workspaces as disabled tabs with a "planned" badge.
- **Do** hold the density: 24px rows and controls, 32px toolbars, 11 to 13px type, tabular figures for numbers.

### Don't:
- **Don't** build a dashboard: no metric cards, no icon sidebar, no slide-in detail drawer.
- **Don't** put method names in coloured pills, and don't colour DELETE red; write methods differ by brightness only.
- **Don't** use status hues as fills, badges, row tints or backgrounds.
- **Don't** use blue as decoration or as a category colour.
- **Don't** add shadows to panes, rows, buttons or headers; shadows belong to floating overlays only.
- **Don't** put a halo or glow on the listener dot.
- **Don't** render the daemon's stored raw head; it contains clear-text secrets.
- **Don't** render captured HTML or run captured scripts; preview raster images only.
- **Don't** load fonts, icons or any asset from the network.
- **Don't** borrow Burp Suite or PortSwigger trade dress, layout, colour scheme or iconography.
