/**
 * Best-effort client-side redaction for the "preview before send" step. This is a safety net so a
 * prompt sent to the user's model does not obviously carry credentials by default - the user can
 * always turn it off to send raw. It is deliberately conservative and pattern-based.
 */
export function redactSecrets(text: string): string {
  return text
    // Auth / key / cookie headers (whole value).
    .replace(/^(authorization:\s*)(bearer\s+|basic\s+|digest\s+)?\S.*$/gim, (_m, p: string, scheme?: string) => `${p}${scheme ?? ''}[REDACTED]`)
    .replace(/^(proxy-authorization:\s*)\S.*$/gim, '$1[REDACTED]')
    .replace(/^(x-api-key:\s*)\S.*$/gim, '$1[REDACTED]')
    .replace(/^(cookie:\s*)\S.*$/gim, '$1[REDACTED]')
    .replace(/^(set-cookie:\s*)\S.*$/gim, '$1[REDACTED]')
    // Common token shapes anywhere.
    .replace(/\bsk-[A-Za-z0-9_-]{10,}\b/g, '[REDACTED]')
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\b/g, '[REDACTED-JWT]')
    // key=value / "key": "value" for sensitive names.
    .replace(/((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token)"?\s*[:=]\s*"?)[^"'&\s,}]+/gi, '$1[REDACTED]');
}
