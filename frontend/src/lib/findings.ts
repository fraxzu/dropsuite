/**
 * Passive response analysis for the Replay viewer. These are read-only checks on a response that
 * was already fetched: missing or weak security headers, information disclosure, insecure cookies,
 * reflected input, risky CORS, and error/stack-trace leakage. Nothing is sent; this only reads.
 */
export type Severity = 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  severity: Severity;
  title: string;
  detail: string;
}

const RANK: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };

interface Input {
  url: string;
  status: number;
  headers: [string, string][];
  body: string;
  /** Values of the request's query/body parameters, for reflection checks. */
  paramValues: string[];
}

const get = (headers: [string, string][], name: string): string | undefined =>
  headers.find(([k]) => k.toLowerCase() === name.toLowerCase())?.[1];

const getAll = (headers: [string, string][], name: string): string[] =>
  headers.filter(([k]) => k.toLowerCase() === name.toLowerCase()).map(([, v]) => v);

export function analyzeResponse(input: Input): Finding[] {
  const { url, status, headers, body } = input;
  const out: Finding[] = [];
  const https = url.toLowerCase().startsWith('https://');

  // --- Security headers ---------------------------------------------------------------------
  const csp = get(headers, 'content-security-policy');
  if (!csp) {
    out.push({ severity: 'medium', title: 'Missing Content-Security-Policy', detail: 'No CSP header. A policy limits where scripts/resources can load from and is a key XSS mitigation.' });
  } else if (!/default-src|script-src/i.test(csp)) {
    out.push({ severity: 'low', title: 'Weak Content-Security-Policy', detail: `CSP has no default-src or script-src, so it does little against XSS: "${csp.slice(0, 80)}".` });
  }
  if (!get(headers, 'x-content-type-options')) {
    out.push({ severity: 'low', title: 'Missing X-Content-Type-Options', detail: 'Without "nosniff", browsers may MIME-sniff responses, enabling some content-type attacks.' });
  }
  if (!get(headers, 'x-frame-options') && !/frame-ancestors/i.test(csp ?? '')) {
    out.push({ severity: 'medium', title: 'No clickjacking protection', detail: 'No X-Frame-Options and no CSP frame-ancestors: the page can be framed (clickjacking).' });
  }
  if (https && !get(headers, 'strict-transport-security')) {
    out.push({ severity: 'medium', title: 'Missing HSTS', detail: 'HTTPS response without Strict-Transport-Security: downgrade/SSL-strip attacks are not prevented.' });
  }
  if (!get(headers, 'referrer-policy')) {
    out.push({ severity: 'info', title: 'No Referrer-Policy', detail: 'The Referer header may leak URLs (with tokens) to other sites.' });
  }

  // --- Information disclosure ----------------------------------------------------------------
  const server = get(headers, 'server');
  if (server && /\d/.test(server)) {
    out.push({ severity: 'low', title: 'Server version disclosed', detail: `Server header reveals software and version: "${server}". Helps an attacker match known CVEs.` });
  }
  for (const h of ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator']) {
    const v = get(headers, h);
    if (v) out.push({ severity: 'low', title: `Technology disclosed (${h})`, detail: `"${h}: ${v}" reveals the backend technology.` });
  }

  // --- Cookies -------------------------------------------------------------------------------
  for (const c of getAll(headers, 'set-cookie')) {
    const name = c.split('=')[0]?.trim() ?? 'cookie';
    const flags = c.toLowerCase();
    if (https && !flags.includes('secure')) out.push({ severity: 'medium', title: `Cookie without Secure (${name})`, detail: 'A cookie without Secure can be sent over plain HTTP and intercepted.' });
    if (!flags.includes('httponly')) out.push({ severity: 'medium', title: `Cookie without HttpOnly (${name})`, detail: 'A cookie readable by JavaScript can be stolen via XSS.' });
    if (!flags.includes('samesite')) out.push({ severity: 'low', title: `Cookie without SameSite (${name})`, detail: 'No SameSite attribute weakens CSRF protection.' });
  }

  // --- CORS ----------------------------------------------------------------------------------
  const acao = get(headers, 'access-control-allow-origin');
  if (acao === '*') {
    const creds = (get(headers, 'access-control-allow-credentials') ?? '').toLowerCase() === 'true';
    out.push({
      severity: creds ? 'high' : 'low',
      title: 'Permissive CORS',
      detail: creds ? 'Access-Control-Allow-Origin: * with credentials allowed exposes authenticated data to any origin.' : 'Access-Control-Allow-Origin: * lets any site read this response.',
    });
  }

  // --- Reflected input (possible XSS) --------------------------------------------------------
  for (const v of input.paramValues) {
    if (v.length < 3) continue;
    if (body.includes(v)) {
      const marker = /[<>"'`]/.test(v);
      out.push({
        severity: marker ? 'high' : 'medium',
        title: marker ? 'Input reflected unencoded (possible XSS)' : 'Input reflected in response',
        detail: `The value "${v.slice(0, 60)}" appears verbatim in the response body${marker ? ', including special characters that were not encoded' : ''}.`,
      });
      break; // one reflection finding is enough signal
    }
  }

  // --- Body signals --------------------------------------------------------------------------
  const low = body.slice(0, 20000).toLowerCase();
  if (/(sql syntax|mysql_fetch|ora-\d{5}|unclosed quotation mark|psql:|sqlstate|you have an error in your sql)/i.test(low)) {
    out.push({ severity: 'high', title: 'Possible SQL error leaked', detail: 'The response contains database error text, a strong signal of SQL injection.' });
  }
  if (/(traceback \(most recent call last\)|exception in thread|stack trace:|at [\w.$]+\([\w.]+\.java:\d+\)|\.php on line \d+)/i.test(low)) {
    out.push({ severity: 'medium', title: 'Stack trace / error disclosed', detail: 'The response leaks a stack trace or server error, revealing internal paths and logic.' });
  }
  if (/<title>index of \//i.test(low) || /\[to parent directory\]/i.test(low)) {
    out.push({ severity: 'medium', title: 'Directory listing', detail: 'The server returned a directory listing, exposing files that should not be browsable.' });
  }
  if (status >= 500) {
    out.push({ severity: 'info', title: `Server error (${status})`, detail: 'A 5xx status can indicate an unhandled condition worth probing.' });
  }

  out.sort((a, b) => RANK[a.severity] - RANK[b.severity]);
  return out;
}

export function topSeverity(findings: Finding[]): Severity | null {
  return findings.length ? findings.reduce((s, f) => (RANK[f.severity] < RANK[s] ? f.severity : s), 'info' as Severity) : null;
}
