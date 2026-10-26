// DropSuite logo candidates, round 2 (minimal monochrome direction).
// 64-unit grid: multiples of 4 land on whole pixels at 16px. Single colour by design;
// every part takes the same fill, so dark, light and one-colour variants are just a fill swap.
const DS2_CANDIDATES = [
  {
    id: 'a',
    letter: 'A',
    name: 'Split Geometry',
    concept:
      'A square split on one 45° bias, its two halves slipped apart along the cut. Request and response, held apart by a clean channel: DropSuite is the space between them.',
    paths: ['M10 8h40L10 48z', 'M54 20v36H18z'],
  },
  {
    id: 'b',
    letter: 'B',
    name: 'Abstract D',
    concept:
      'A solid D cut once, top to bottom: a column and a half-disc separated by a single fine incision. No outline and no counter. The cut is the line between client and server where DropSuite sits. (Revised: the first draft’s wide gap read as the letters "ID".)',
    paths: ['M12 8h12v48H12z', 'M28 8a24 24 0 0 1 0 48z'],
  },
  {
    id: 'c',
    letter: 'C',
    name: 'DS Signature',
    concept:
      'Two half-discs turned against each other across a narrow channel. Together they trace an S; the lower one alone is a D. The channel between them is the line traffic passes through.',
    paths: ['M28 8A16 16 0 0 0 28 40z', 'M36 24a16 16 0 0 1 0 32z'],
  },
];

function ds2Svg(c, size, fill, extra = '') {
  const paths = c.paths.map((d) => `<path d="${d}"/>`).join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 64 64" fill="${fill}" ${extra}>${paths}</svg>`;
}

if (typeof module !== 'undefined') module.exports = { DS2_CANDIDATES, ds2Svg };
