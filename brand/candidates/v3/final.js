// DropSuite V3 finalists. 64-unit grid, single colour; every path takes the same fill.
// The Cut Drop geometry is computed (circle r22 + tangents to the apex, a 6-unit cut band at 15°,
// lower piece slid 5 units along the cut) and emitted as plain paths, so no clip masks are needed.
const V3 = [
  {
    id: 'a',
    letter: 'A',
    name: 'Cut Drop',
    territory: 'Controlled interception',
    idea:
      'The name made into a shape: a drop built from one circle and two tangents, cut cleanly by a 15° blade and slid along the cut. Something in flight, stopped at one precise point: what DropSuite does to a request. The silhouette survives the cut, so it stays a drop at any size.',
    paths: [
      'M29.59 2L47.52 27.26A22 22 0 0 1 49.02 29.69L7.6 40.79A22 22 0 0 1 11.65 27.26Z',
      'M55.92 34.05A22 22 0 0 1 13.47 45.42Z',
    ],
    scores: { Originality: 4, Memorability: 5, 'Small-size legibility': 4, 'Visual balance': 4, 'Brand relevance': 5, Distinctiveness: 3 },
    weakness:
      'Drops are among the most common shapes on stock logo marketplaces, so the cut is doing all the ownership work; without it this is a stock icon. At 16 px the cut is about 1.5 px wide, so it is visible but soft. The apex is slightly sharper than the body is heavy; a final pass should tune the tangent angle optically.',
    similarity:
      'No technology brand with a cut or sliced drop came up. The nearest results were generic water-drop templates and water-treatment companies (Aquaporin), which use drops without a cut.',
  },
  {
    id: 'b',
    letter: 'B',
    name: 'Round Trip',
    territory: 'Data transformation',
    idea:
      'One heavy stroke goes out, turns through a perfect half-turn and comes back: request, then response. It enters square-cut (raw) and exits on a precise bevel (controlled), and the return arm is shorter than the outbound one. The counter inside is the space where the exchange is held.',
    paths: ['M4 8H36A24 24 0 0 1 36 56H16L30 42H36A10 10 0 0 0 36 22H4Z'],
    scores: { Originality: 3, Memorability: 3, 'Small-size legibility': 5, 'Visual balance': 4, 'Brand relevance': 4, Distinctiveness: 3 },
    weakness:
      'At a glance it can read as an open D, a magnet or a paperclip end. Its meaning depends on the asymmetry (long out, short bevelled return), which is subtle at 16 px. Very legible, but the least emotional of the three.',
    similarity:
      'No brand with this hairpin construction came up. Rounded bracket and U-turn forms are common in stock "tech" templates, so the bevelled exit has to stay to keep it ownable.',
  },
  {
    id: 'c',
    letter: 'C',
    name: 'Drop-d',
    territory: 'Abstract signature',
    idea:
      'A lowercase d whose ascender is the tail of a falling drop: one continuous form that fuses the name and the initial. A sharp vertical back, a full round bowl and one concave sweep into the point.',
    paths: ['M52 4V40A20 20 0 1 1 32 20Q48 20 52 4Z'],
    scores: { Originality: 2, Memorability: 4, 'Small-size legibility': 4, 'Visual balance': 3, 'Brand relevance': 4, Distinctiveness: 2 },
    weakness:
      'Letter-inside-a-drop is a recognised stock template category ("letter D water drop logo"), so it risks looking bought rather than designed. It is right-heavy at small sizes, and its friendly, liquid character pulls away from the "bold, precise, technical" brief.',
    similarity:
      'Close to many stock "letter + water drop" templates. Among named brands, the d2W droplet (Degradable Plastics) also pairs a lowercase d with a droplet. This is the weakest candidate on distinctiveness.',
  },
];

function v3Svg(c, size, fill) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 64 64" fill="${fill}">${c.paths.map((d) => `<path d="${d}"/>`).join('')}</svg>`;
}

if (typeof module !== 'undefined') module.exports = { V3, v3Svg };
