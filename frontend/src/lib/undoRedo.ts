/**
 * Global undo/redo for every text field in the app.
 *
 * All our inputs are controlled React components (`value` + `onChange`), which wipes the browser's
 * own undo stack on each keystroke - so Ctrl+Z does nothing useful. This installs a per-element
 * history (keyed by the element via a WeakMap) and handles Ctrl+Z / Ctrl+Y / Ctrl+Shift+Z.
 *
 * On undo/redo we restore the value through the element's native value setter and dispatch a real
 * `input` event, so React's onChange runs and controlled state updates in lockstep.
 */

interface Snap {
  value: string;
  start: number;
  end: number;
}
interface Hist {
  stack: Snap[];
  index: number;
  lastTime: number;
}

const MAX = 200;
const COALESCE_MS = 350;
const hist = new WeakMap<HTMLInputElement | HTMLTextAreaElement, Hist>();
let applying = false;

type Field = HTMLInputElement | HTMLTextAreaElement;

const EDITABLE_INPUT = new Set(['text', 'search', 'url', 'email', 'tel', 'password', 'number', '']);

function isField(el: EventTarget | null): el is Field {
  if (el instanceof HTMLTextAreaElement) return !el.disabled && !el.readOnly;
  if (el instanceof HTMLInputElement) return !el.disabled && !el.readOnly && EDITABLE_INPUT.has(el.type);
  return false;
}

function snap(el: Field): Snap {
  return { value: el.value, start: el.selectionStart ?? el.value.length, end: el.selectionEnd ?? el.value.length };
}

function ensure(el: Field): Hist {
  let h = hist.get(el);
  if (!h) {
    h = { stack: [snap(el)], index: 0, lastTime: 0 };
    hist.set(el, h);
  }
  return h;
}

const nativeSetter = (el: Field) => {
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  return Object.getOwnPropertyDescriptor(proto, 'value')?.set;
};

function apply(el: Field, s: Snap) {
  applying = true;
  try {
    nativeSetter(el)?.call(el, s.value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    try {
      el.setSelectionRange(s.start, s.end);
    } catch {
      /* number inputs don't support selection */
    }
  } finally {
    applying = false;
  }
}

function record(el: Field) {
  const h = ensure(el);
  // Drop any redo tail.
  if (h.index < h.stack.length - 1) h.stack.length = h.index + 1;
  const now = Date.now();
  const cur = snap(el);
  if (cur.value === h.stack[h.index]?.value) {
    h.stack[h.index] = cur; // selection-only change
    h.lastTime = now;
    return;
  }
  if (now - h.lastTime < COALESCE_MS && h.index > 0) {
    h.stack[h.index] = cur; // coalesce a burst of typing into one step
  } else {
    h.stack.push(cur);
    h.index++;
    if (h.stack.length > MAX) {
      h.stack.shift();
      h.index--;
    }
  }
  h.lastTime = now;
}

export function installUndoRedo() {
  // Seed history when a field gains focus, so the first undo returns to the pre-edit text.
  document.addEventListener(
    'focusin',
    (e) => {
      if (isField(e.target)) ensure(e.target);
    },
    true,
  );

  document.addEventListener(
    'input',
    (e) => {
      if (applying) return;
      if (isField(e.target)) record(e.target);
    },
    true,
  );

  document.addEventListener(
    'keydown',
    (e) => {
      const mod = e.ctrlKey || e.metaKey;
      if (!mod) return;
      const key = e.key.toLowerCase();
      const isUndo = key === 'z' && !e.shiftKey;
      const isRedo = key === 'y' || (key === 'z' && e.shiftKey);
      if (!isUndo && !isRedo) return;
      if (!isField(e.target)) return;
      const el = e.target;
      const h = hist.get(el);
      if (!h) return;

      if (isUndo && h.index > 0) {
        h.index--;
        apply(el, h.stack[h.index]);
        e.preventDefault();
        e.stopPropagation();
      } else if (isRedo && h.index < h.stack.length - 1) {
        h.index++;
        apply(el, h.stack[h.index]);
        e.preventDefault();
        e.stopPropagation();
      } else if (isUndo || isRedo) {
        // Nothing to do, but swallow so WebView2 doesn't run its own broken undo.
        e.preventDefault();
      }
    },
    true,
  );
}
