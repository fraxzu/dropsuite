// Exact geometry for the V4 Cut Drop family. Drop = circle (32,40) r22 + tangents to apex (32,2).
const R = 22, CX = 32, CY = 40, APEX = [32, 2];
const phi = Math.acos(R / (CY - APEX[1]));
const TR = [CX + R * Math.sin(phi), CY - R * Math.cos(phi)];
const TL = [CX - R * Math.sin(phi), CY - R * Math.cos(phi)];
// Circle ∩ line y = m x + b: returns [left, right].
function hit(m, b) {
  const A = 1 + m * m, B = -2 * CX + 2 * m * (b - CY), C = CX * CX + (b - CY) ** 2 - R * R;
  const s = Math.sqrt(B * B - 4 * A * C);
  const xs = [(-B - s) / (2 * A), (-B + s) / (2 * A)];
  return xs.map((x) => [x, m * x + b]);
}
const rot = (p, c, deg) => {
  const a = (deg * Math.PI) / 180, dx = p[0] - c[0], dy = p[1] - c[1];
  return [c[0] + dx * Math.cos(a) - dy * Math.sin(a), c[1] + dx * Math.sin(a) + dy * Math.cos(a)];
};
// Paths are built as command lists so they can be transformed, measured and printed exactly.
const P = (cmds) => cmds;
function fmt(cmds, t = (p) => p, rr = R) {
  const n = (v) => (Math.round(v * 100) / 100).toString();
  const ang = (p) => Math.atan2(p[1] - CY, p[0] - CX);
  let prev = null;
  return cmds.map(([op, ...a]) => {
    if (op === 'M' || op === 'L') { prev = a[0]; const p = t(a[0]); return `${op}${n(p[0])} ${n(p[1])}`; }
    if (op === 'A') {
      // Span measured on the untransformed circle; rotation and uniform scale preserve it.
      let span = ang(a[2]) - ang(prev);
      if (a[1] === 1) { while (span < 0) span += 2 * Math.PI; } else { while (span > 0) span -= 2 * Math.PI; span = -span; }
      const large = span > Math.PI ? 1 : 0;
      prev = a[2];
      const p = t(a[2]);
      return `A${n(rr)} ${n(rr)} 0 ${large} ${a[1]} ${n(p[0])} ${n(p[1])}`;
    }
    return 'Z';
  }).join('');
}
function points(cmds) { return cmds.filter((c) => c[0] !== 'Z').map((c) => (c[0] === 'A' ? c[3] : c[1])); }
// Bounding box including the circle's extreme points that fall inside each arc.
function bbox(pieces) {
  const pts = pieces.flatMap((pc) => points(pc.cmds).map(pc.t));
  return [Math.min(...pts.map((p) => p[0])), Math.min(...pts.map((p) => p[1])), Math.max(...pts.map((p) => p[0])), Math.max(...pts.map((p) => p[1]))];
}
const out = {};

// A1 · Precision Fracture: Z-shaped lap-joint seam, 5-unit gap, no displacement.
{
  const X = 32, Y1 = 33, Y2 = 45, g = 2.5;
  const [L1] = hit(0, Y1 - g), [, R2] = hit(0, Y2 - g), [L3] = hit(0, Y1 + g), [, R3] = hit(0, Y2 + g);
  const upper = P([['M', L1], ['A', 0, 1, TL], ['L', APEX], ['L', TR], ['A', 0, 1, R2], ['L', [X + g, Y2 - g]], ['L', [X + g, Y1 - g]], ['Z']]);
  const lower = P([['M', R3], ['A', 1, 1, L3], ['L', [X - g, Y1 + g]], ['L', [X - g, Y2 + g]], ['Z']]);
  out.a1 = [fmt(upper), fmt(lower)];
}

// A2 · Intercepted Offset: cut on a 9/64 slope, top piece hinged open 12° about a point inside the left edge.
{
  const m = -9 / 64, b1 = 40, b2 = 42, pivot = [11, 39], ang = -12;
  const [L1, R1] = hit(m, b1), [L2, R2] = hit(m, b2);
  const upper = P([['M', L1], ['A', 0, 1, TL], ['L', APEX], ['L', TR], ['A', 0, 1, R1], ['Z']]);
  const lower = P([['M', R2], ['A', 1, 1, L2], ['Z']]);
  const tu = (p) => rot(p, pivot, ang), id = (p) => p;
  const pts = [...points(upper).map(tu), APEX && tu(APEX), [CX - R, CY], [CX + R, CY], [CX, CY + R]];
  const minX = Math.min(...pts.map((p) => p[0])), maxX = Math.max(...pts.map((p) => p[0]));
  const minY = Math.min(...pts.map((p) => p[1])), maxY = Math.max(...pts.map((p) => p[1]));
  const sc = Math.min(1, 60 / (maxY - minY));
  const fit = (p) => [32 + (p[0] - (minX + maxX) / 2) * sc, 32 + (p[1] - (minY + maxY) / 2) * sc];
  out.a2 = [fmt(upper, (p) => fit(tu(p)), R * sc), fmt(lower, fit, R * sc)];
  out.a2scale = sc;
}

// A3 · Negative-Space Capture: a tapered blade enters from the right and stops past centre; one piece.
{
  const tip = [17, 42];
  const top = [64, 28], bot = [64, 36];
  const m1 = (top[1] - tip[1]) / (top[0] - tip[0]), b1 = tip[1] - m1 * tip[0];
  const m2 = (bot[1] - tip[1]) / (bot[0] - tip[0]), b2 = tip[1] - m2 * tip[0];
  const [, Rb1] = hit(m1, b1), [, Rb2] = hit(m2, b2);
  const body = P([['M', APEX], ['L', TR], ['A', 0, 1, Rb1], ['L', tip], ['L', Rb2], ['A', 1, 1, TL], ['Z']]);
  out.a3 = [fmt(body)];
}
console.log(JSON.stringify(out, null, 1));
