/**
 * Pull the security-relevant parts out of an HTML response body so an AI review can reason about
 * forms, inputs, scripts, endpoints and comments without being fed the whole page. Regex-based and
 * best-effort: this is a compact summary for a prompt, not a parser.
 */
function uniq(items: string[], cap: number): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const it of items) {
    const t = it.trim();
    if (!t || seen.has(t)) continue;
    seen.add(t);
    out.push(t);
    if (out.length >= cap) break;
  }
  return out;
}

export function extractHtmlSummary(body: string, maxChars = 6000): string {
  const forms = uniq([...body.matchAll(/<form\b[^>]*>/gi)].map((m) => m[0].replace(/\s+/g, ' ')), 15);
  const inputs = uniq(
    [...body.matchAll(/<(?:input|select|textarea|button)\b[^>]*>/gi)].map((m) => m[0].replace(/\s+/g, ' ')),
    40,
  );
  const scriptSrc = uniq([...body.matchAll(/<script\b[^>]*\bsrc=["']?([^"'\s>]+)/gi)].map((m) => m[1]), 30);
  const endpoints = uniq(
    [...body.matchAll(/\b(?:href|action|data-url|data-href)=["']([^"']+)["']/gi)].map((m) => m[1]).filter((u) => !u.startsWith('#') && !u.startsWith('javascript:') && !u.startsWith('mailto:')),
    40,
  );
  const comments = uniq(
    [...body.matchAll(/<!--([\s\S]*?)-->/g)].map((m) => m[1].trim()).filter((c) => c && !/^\[if /.test(c)),
    10,
  ).map((c) => (c.length > 160 ? c.slice(0, 160) + '…' : c));
  const inline = [...body.matchAll(/<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)]
    .map((m) => m[1].trim())
    .filter(Boolean)
    .join('\n')
    .slice(0, 1500);

  const sections: string[] = [];
  const add = (title: string, items: string[]) => {
    if (items.length) sections.push(`${title} (${items.length}):\n${items.join('\n')}`);
  };
  add('Forms', forms);
  add('Input fields', inputs);
  add('External scripts', scriptSrc);
  add('Linked endpoints', endpoints);
  add('HTML comments', comments);
  if (inline) sections.push(`Inline script (first 1.5KB):\n${inline}`);

  const text = sections.join('\n\n');
  if (!text) return '(no forms, inputs, scripts, or links found in the body)';
  return text.length > maxChars ? text.slice(0, maxChars) + '\n… (summary truncated)' : text;
}

/** Split a raw HTTP message into its head (status line + headers) and body. */
export function splitHeadBody(message: string): { head: string; body: string } {
  const i = message.indexOf('\r\n\r\n');
  const j = i === -1 ? message.indexOf('\n\n') : i;
  if (j === -1) return { head: message, body: '' };
  const sep = message[j] === '\r' ? 4 : 2;
  return { head: message.slice(0, j), body: message.slice(j + sep) };
}
