/**
 * Decide whether a discovery run really tested paths or just hit one refusal over and over.
 *
 * Edge protection answers every unknown path with the same block page (same status, near-identical
 * length). Without this check the table shows a hundred "findings" that are one page repeated.
 */
export interface DiscSample {
  path: string;
  status: number;
  length: number;
}

export interface DominantRefusal {
  status: number;
  length: number;
  share: number;
}

/** Share of refusals that must agree before the run is called blocked, and the minimum sample. */
const MIN_GROUP = 8;
const MIN_SHARE = 0.8;
/** Lengths may differ by a little (timestamps, ray ids); 15% or 64 bytes is the tolerance. */
const LENGTH_TOLERANCE = 0.15;

export function dominantRefusal(rows: DiscSample[], sentinels: Set<string>): DominantRefusal | null {
  const refusals = rows.filter((r) => !sentinels.has(r.path) && r.status >= 400);
  if (refusals.length < MIN_GROUP) return null;

  const counts = new Map<number, DiscSample[]>();
  for (const row of refusals) {
    const list = counts.get(row.status) ?? [];
    list.push(row);
    counts.set(row.status, list);
  }
  const [status, group] = [...counts.entries()].sort((a, b) => b[1].length - a[1].length)[0];
  if (group.length / refusals.length < MIN_SHARE) return null;

  const lengths = group.map((r) => r.length);
  const max = Math.max(...lengths);
  const min = Math.min(...lengths);
  if (max - min > Math.max(64, max * LENGTH_TOLERANCE)) return null;

  const length = Math.round(lengths.reduce((a, b) => a + b, 0) / lengths.length);
  return { status, length, share: Math.round((group.length / refusals.length) * 100) };
}
