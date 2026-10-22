// DropSuite mark: an isometric slab and a folded "7" slab, every slanted edge at 30°.
// 64-unit grid. Vertical edges sit on x = 12, 36, 44, 52 (whole pixels at 16 px).
// Horizontal gap between slab and fold: 8. Vertical gap on the diagonal: 9 (≈ 7.8 perpendicular,
// slightly wider than its measured share so the diagonal does not read thinner than the vertical).
const s = Math.tan(Math.PI / 6);
const B = 3.76;                 // top of the fold, chosen so the mark is vertically centred
const band = 14;                // vertical thickness of the fold's top band
const r = (v) => Math.round(v * 100) / 100;
// Fold ("7"): band from x 30 to 52, column from x 44 to 52.
const fold = [[30, B], [52, B + 22 * s], [52, B + 46], [44, B + 46 - 8 * s], [44, B + band + 14 * s], [30, B + band]];
// Slab: x 12 to 36; its top edge sits 9 units below the band's bottom edge at every x.
const slabTopLeft = B + band + 9 - 18 * s; // band bottom at x=30 is B+band; at x=12 the parallel line is 18s higher
const slab = [[12, slabTopLeft], [36, slabTopLeft + 24 * s], [36, slabTopLeft + 24 * s + 30], [12, slabTopLeft + 30]];
const path = (pts) => 'M' + pts.map(([x, y]) => `${r(x)} ${r(y)}`).join('L') + 'Z';
const ys = [...fold, ...slab].map((p) => p[1]);
console.log(JSON.stringify({ fold: path(fold), slab: path(slab), top: r(Math.min(...ys)), bottom: r(Math.max(...ys)),
  gapCheck: r((slabTopLeft + 18 * s) - (B + band)) }, null, 1));
