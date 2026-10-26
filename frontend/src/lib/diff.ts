/**
 * Line diff for comparing two Replay responses. Bodies are at most 16 KB (the capture limit),
 * so after trimming the common prefix and suffix an exact LCS on the changed middle is cheap.
 * When that middle is still too large, lines are compared by position and the result is
 * flagged `approximate`.
 */

export type RowKind = 'same' | 'changed' | 'removed' | 'added';

export interface DiffRow {
  kind: RowKind;
  left?: { no: number; text: string };
  right?: { no: number; text: string };
}

export interface DiffResult {
  rows: DiffRow[];
  approximate: boolean;
  added: number;
  removed: number;
  changed: number;
}

type Op = { kind: 'equal' | 'del' | 'add'; a?: number; b?: number };

const MAX_CELLS = 4_000_000;

function middleOps(a: string[], b: string[], aOff: number, bOff: number): { ops: Op[]; approximate: boolean } {
  const n = a.length;
  const m = b.length;
  if (n * m > MAX_CELLS || n > 65000 || m > 65000) {
    const ops: Op[] = [];
    for (let i = 0; i < Math.max(n, m); i++) {
      if (i < n && i < m && a[i] === b[i]) ops.push({ kind: 'equal', a: aOff + i, b: bOff + i });
      else {
        if (i < n) ops.push({ kind: 'del', a: aOff + i });
        if (i < m) ops.push({ kind: 'add', b: bOff + i });
      }
    }
    return { ops, approximate: true };
  }
  // LCS lengths from the end: lcs[i][j] for a[i..], b[j..].
  const w = m + 1;
  const lcs = new Uint16Array((n + 1) * w);
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i * w + j] = a[i] === b[j] ? lcs[(i + 1) * w + j + 1] + 1 : Math.max(lcs[(i + 1) * w + j], lcs[i * w + j + 1]);
    }
  }
  const ops: Op[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      ops.push({ kind: 'equal', a: aOff + i++, b: bOff + j++ });
    } else if (lcs[(i + 1) * w + j] >= lcs[i * w + j + 1]) {
      ops.push({ kind: 'del', a: aOff + i++ });
    } else {
      ops.push({ kind: 'add', b: bOff + j++ });
    }
  }
  while (i < n) ops.push({ kind: 'del', a: aOff + i++ });
  while (j < m) ops.push({ kind: 'add', b: bOff + j++ });
  return { ops, approximate: false };
}

export function diffLines(a: string[], b: string[]): DiffResult {
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length;
  let endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
    endA--;
    endB--;
  }
  const mid = middleOps(a.slice(start, endA), b.slice(start, endB), start, start);
  const ops: Op[] = [];
  for (let k = 0; k < start; k++) ops.push({ kind: 'equal', a: k, b: k });
  ops.push(...mid.ops);
  for (let k = 0; k < a.length - endA; k++) ops.push({ kind: 'equal', a: endA + k, b: endB + k });

  // Pair runs of removed and added lines into "changed" rows.
  const rows: DiffRow[] = [];
  let added = 0;
  let removed = 0;
  let changed = 0;
  for (let k = 0; k < ops.length; ) {
    if (ops[k].kind === 'equal') {
      const { a: ai, b: bi } = ops[k];
      rows.push({ kind: 'same', left: { no: ai! + 1, text: a[ai!] }, right: { no: bi! + 1, text: b[bi!] } });
      k++;
      continue;
    }
    const dels: number[] = [];
    const adds: number[] = [];
    while (k < ops.length && ops[k].kind !== 'equal') {
      if (ops[k].kind === 'del') dels.push(ops[k].a!);
      else adds.push(ops[k].b!);
      k++;
    }
    for (let x = 0; x < Math.max(dels.length, adds.length); x++) {
      const l = dels[x];
      const r = adds[x];
      if (l !== undefined && r !== undefined) {
        rows.push({ kind: 'changed', left: { no: l + 1, text: a[l] }, right: { no: r + 1, text: b[r] } });
        changed++;
      } else if (l !== undefined) {
        rows.push({ kind: 'removed', left: { no: l + 1, text: a[l] } });
        removed++;
      } else {
        rows.push({ kind: 'added', right: { no: r + 1, text: b[r] } });
        added++;
      }
    }
  }
  return { rows, approximate: mid.approximate, added, removed, changed };
}
