/**
 * Parse a pasted or loaded wordlist for content discovery.
 *
 * One path per line, `#` starts a comment, surrounding slashes are normalised away, duplicates and
 * blanks are dropped. The result is capped so a huge SecLists file cannot queue more requests than
 * the engine will finish in a reasonable time.
 */
export const MAX_WORDLIST = 20000;

export function parseWordlist(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of text.replace(/^\uFEFF/, '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const path = line.replace(/^\/+/, '').replace(/\/+$/, '');
    if (!path || seen.has(path)) continue;
    seen.add(path);
    out.push(path);
    if (out.length >= MAX_WORDLIST) break;
  }
  return out;
}
