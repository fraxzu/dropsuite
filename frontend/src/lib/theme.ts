// App theme. Themes are just a set of CSS custom properties swapped under a data-theme attribute
// on <html>; every surface already reads its colors from those tokens, so switching is instant and
// needs no React re-render. The value is persisted with the same `dropsuite.<key>` convention as
// useStoredState so both agree on where it lives.

export type ThemeId = 'dark' | 'light';

export const THEME_KEY = 'app.theme';
const STORAGE_KEY = `dropsuite.${THEME_KEY}`;

export const DEFAULT_THEME: ThemeId = 'dark';

export const THEMES: { id: ThemeId; label: string; hint: string }[] = [
  { id: 'dark', label: 'Dark', hint: 'The default, tuned for long sessions in a dim room.' },
  { id: 'light', label: 'Light', hint: 'A bright theme for well-lit rooms and screenshots.' },
];

function isTheme(v: unknown): v is ThemeId {
  return v === 'dark' || v === 'light';
}

/** The saved theme, or the default when nothing is saved or storage is unavailable. */
export function readStoredTheme(): ThemeId {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw === null) return DEFAULT_THEME;
    const parsed = JSON.parse(raw);
    return isTheme(parsed) ? parsed : DEFAULT_THEME;
  } catch {
    return DEFAULT_THEME;
  }
}

/** Put the theme on <html> so the token overrides take effect. */
export function applyTheme(id: ThemeId): void {
  document.documentElement.dataset.theme = id;
}
