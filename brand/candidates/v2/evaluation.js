// Scores 1 to 5, judged from the renders on this sheet.
(() => {
  const [A, B, C] = DS2_CANDIDATES;
  document.getElementById('eval').innerHTML = `
<h2>Evaluation</h2>
<table class="score">
  <thead><tr><th>Criterion</th><th>A · Split Geometry</th><th>B · Abstract D</th><th>C · DS Signature</th></tr></thead>
  <tbody>
    <tr><td>Originality</td><td class="n">2</td><td class="n">3</td><td class="n">5</td></tr>
    <tr><td>Recognizability (silhouette)</td><td class="n">3</td><td class="n">5</td><td class="n">5</td></tr>
    <tr><td>Premium quality</td><td class="n">4</td><td class="n">4</td><td class="n">5</td></tr>
    <tr><td>Scalability, 16 to 256 px</td><td class="n">5</td><td class="n">5</td><td class="n">4</td></tr>
    <tr><td>Alignment and fit with the UI</td><td class="n">4</td><td class="n">5</td><td class="n">5</td></tr>
    <tr><td><strong>Total</strong></td><td class="n">18</td><td class="n">22</td><td class="n">24</td></tr>
    <tr>
      <td>Distance from Lighter</td>
      <td class="note"><strong>Moderate.</strong> Different construction (two triangles from a split square, not vertical slabs side by side), but it shares Lighter's solid-white, 45°-only grammar. The closest of the three.</td>
      <td class="note"><strong>Clear.</strong> Built from an orthogonal column and a curve. No shared construction, angle or composition.</td>
      <td class="note"><strong>Clear.</strong> All curves and a vertical channel. No shared construction, angle or composition.</td>
    </tr>
    <tr>
      <td>Distance from other known marks</td>
      <td class="note">Weak. A diagonally split square is a stock UI glyph (contrast and aspect-ratio icons), so the mark would be hard to own.</td>
      <td class="note">Fair. Column plus bowl is a familiar way to build a D. The nearest well-known mark, Patreon's 2013–2020 bar and full circle, differs in both form and gap. The first draft read as "ID" and was revised.</td>
      <td class="note">Good. Two offset half-discs as an S is a known geometric idea, but no specific well-known mark came up in this check. Have a formal trademark search done before adoption.</td>
    </tr>
    <tr>
      <td>Honest risk</td>
      <td class="note">Clean but anonymous: most people would not remember it as DropSuite.</td>
      <td class="note">Very legible, but the safest of the three. Its recall depends on the single incision.</td>
      <td class="note">Reads as an S before a D. Each half-disc is only about 4 px wide at 16 px, so it softens slightly at favicon size, though both forms stay distinct.</td>
    </tr>
  </tbody>
</table>

<div class="rec">
  <h3>${ds2Svg(C, 22, '#ececee')} Recommendation: C · DS Signature, with the title-case wordmark</h3>
  <p>It best meets the brief's target of confidence, elegance and simplicity. There are two solid forms and one channel, and nothing else. The silhouette can be remembered and redrawn from memory, and the channel between the half-discs is the product's idea, traffic passing through a controlled line, said in negative space rather than with a literal packet. It is entirely curve-built, which keeps it furthest from Lighter's angular construction, and it holds as two distinct forms at 16 px in white, black and on blue.</p>
  <p>Wordmark: <strong>DropSuite</strong> in title case, Segoe UI Variable Display 600 at −0.02 em. It is legible at the header's 14 px, matches the UI's typography, and stays clear of Lighter's tracked all-caps voice. Uppercase <strong>DROPSUITE</strong> (+0.2 em) looks refined in large lockups but thin and spaced-out at toolbar size, so it is better kept for splash and marketing use.</p>
  <p>Runner-up: B · Abstract D, if you prefer instant legibility over distinctiveness.</p>
</div>`;
})();
