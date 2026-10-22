/**
 * Pure client-side encoders/decoders for the Decoder tool. No network, no engine - everything
 * runs in the webview. Each transform throws an Error with a readable message on invalid input.
 */

export function b64Encode(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function b64Decode(s: string): string {
  const clean = s.replace(/\s+/g, '');
  let bin: string;
  try {
    bin = atob(clean);
  } catch {
    throw new Error('Not valid Base64.');
  }
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

/** Base64url (JWT segments): URL-safe alphabet, padding optional. */
function b64urlDecode(part: string): string {
  let s = part.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return b64Decode(s);
}

export function urlEncode(s: string): string {
  return encodeURIComponent(s);
}

export function urlDecode(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, ' '));
  } catch {
    throw new Error('Not valid URL (percent) encoding.');
  }
}

export function hexEncode(s: string): string {
  const bytes = new TextEncoder().encode(s);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexDecode(s: string): string {
  const clean = s.replace(/\s+/g, '').replace(/^0x/i, '');
  if (clean.length % 2 !== 0 || /[^0-9a-f]/i.test(clean)) throw new Error('Not valid hex.');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  return new TextDecoder().decode(bytes);
}

export function htmlEncode(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));
}

export function htmlDecode(s: string): string {
  // The browser's own parser handles every named and numeric entity.
  const el = document.createElement('textarea');
  el.innerHTML = s;
  return el.value;
}

export function jwtDecode(s: string): string {
  const parts = s.trim().split('.');
  if (parts.length < 2) throw new Error('Not a JWT. Expected header.payload.signature.');
  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(b64urlDecode(parts[0]));
    payload = JSON.parse(b64urlDecode(parts[1]));
  } catch {
    throw new Error('JWT header/payload is not valid Base64url JSON.');
  }
  return JSON.stringify({ header, payload, signature: parts[2] ? '(present, not verified)' : '(none)' }, null, 2);
}

export type TransformId =
  | 'b64-encode'
  | 'b64-decode'
  | 'url-encode'
  | 'url-decode'
  | 'hex-encode'
  | 'hex-decode'
  | 'html-encode'
  | 'html-decode'
  | 'jwt-decode';

const TRANSFORMS: Record<TransformId, (s: string) => string> = {
  'b64-encode': b64Encode,
  'b64-decode': b64Decode,
  'url-encode': urlEncode,
  'url-decode': urlDecode,
  'hex-encode': hexEncode,
  'hex-decode': hexDecode,
  'html-encode': htmlEncode,
  'html-decode': htmlDecode,
  'jwt-decode': jwtDecode,
};

export function applyTransform(id: TransformId, input: string): string {
  return TRANSFORMS[id](input);
}

/** Button groups for the Decoder UI. */
export const TRANSFORM_GROUPS: { label: string; items: { id: TransformId; label: string }[] }[] = [
  {
    label: 'Encode',
    items: [
      { id: 'b64-encode', label: 'Base64' },
      { id: 'url-encode', label: 'URL' },
      { id: 'hex-encode', label: 'Hex' },
      { id: 'html-encode', label: 'HTML' },
    ],
  },
  {
    label: 'Decode',
    items: [
      { id: 'b64-decode', label: 'Base64' },
      { id: 'url-decode', label: 'URL' },
      { id: 'hex-decode', label: 'Hex' },
      { id: 'html-decode', label: 'HTML' },
    ],
  },
  {
    label: 'Smart',
    items: [{ id: 'jwt-decode', label: 'JWT decode' }],
  },
];
