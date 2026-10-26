// DropSuite logo candidates. Single source for the comparison sheet and the exported SVG files.
// Geometry sits on a 32-unit grid with even coordinates, so at 16px every horizontal and
// vertical edge lands on a whole pixel. Minimum feature is 4 units (2px at 16px).
// role "body" takes the neutral colour, role "accent" takes electric blue.
const DROPSUITE_CANDIDATES = [
  {
    id: 'a',
    letter: 'A',
    name: 'Intercept D',
    concept:
      'A chamfered geometric D whose stem is cut open at mid-height. The gap is where traffic enters; the blue packet inside the counter is the request DropSuite holds. The stream is implied by alignment, not drawn.',
    parts: [
      { role: 'body', d: 'M4 14V4h16l8 8v8l-8 8H4V18h6v4h8l4-4v-4l-4-4h-8v4z' },
      { role: 'accent', d: 'M14 14h4v4h-4z' },
    ],
  },
  {
    id: 'b',
    letter: 'B',
    name: 'Packet Flow',
    concept:
      'The wire is cut on a 45° bias and its packet has dropped out of the slot: the literal "drop" in DropSuite. A bolder, grid-fitted evolution of the mark the app ships today; the slanted cut gives the flow a direction.',
    parts: [
      { role: 'body', d: 'M2 6h12l-6 6H2zM22 6h8v6H16z' },
      { role: 'accent', d: 'M9.5 16h5a1.5 1.5 0 0 1 1.5 1.5v5a1.5 1.5 0 0 1-1.5 1.5h-5A1.5 1.5 0 0 1 8 22.5v-5A1.5 1.5 0 0 1 9.5 16z' },
    ],
  },
  {
    id: 'c',
    letter: 'C',
    name: 'DS Monogram',
    concept:
      'One solid block: the outer silhouette is the chamfered D, and two slots cut from opposite sides leave an S inside it. D and S share every pixel.',
    parts: [{ role: 'accent', d: 'M4 4h16l6 6H10v4h18v6l-8 8H4v-6h18v-4H4z' }],
  },
];

const DROPSUITE_PALETTE = {
  dark: { body: '#e6e7ea', accent: '#3d8bff' },
  light: { body: '#18191c', accent: '#2a6fe0' },
};

function dropsuiteSvg(c, size, colors, extra = '') {
  const paths = c.parts.map((p) => `<path d="${p.d}" fill="${colors[p.role]}"/>`).join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 32 32" ${extra}>${paths}</svg>`;
}

if (typeof module !== 'undefined') module.exports = { DROPSUITE_CANDIDATES, DROPSUITE_PALETTE, dropsuiteSvg };
