// Scores are 1 to 5, judged from the renders on this sheet.
document.getElementById('eval').innerHTML = `
<h2>Evaluation</h2>
<table class="score">
  <thead>
    <tr><th>Criterion</th><th>A · Intercept D</th><th>B · Packet Flow</th><th>C · DS Monogram</th></tr>
  </thead>
  <tbody>
    <tr><td>Originality</td><td class="n">4</td><td class="n">3</td><td class="n">3</td></tr>
    <tr><td>Recognizability</td><td class="n">5</td><td class="n">3</td><td class="n">4</td></tr>
    <tr><td>Professional appearance</td><td class="n">5</td><td class="n">3</td><td class="n">4</td></tr>
    <tr><td>Small-size legibility (16–20 px)</td><td class="n">5</td><td class="n">2</td><td class="n">4</td></tr>
    <tr><td>Fit with the existing UI</td><td class="n">5</td><td class="n">4</td><td class="n">3</td></tr>
    <tr><td><strong>Total</strong></td><td class="n">24</td><td class="n">15</td><td class="n">18</td></tr>
    <tr>
      <td>Honest risk</td>
      <td class="note">The packet is 2 px at 16 px: it reads as a dot of blue, not a shape. The mark still works without it.</td>
      <td class="note">Fills only 18 of 32 units vertically, so it looks small next to other icons; the 45° cut softens below 24 px. Not a letter, so it builds no name recall.</td>
      <td class="note">Reads first as an S (or a 5); the D lives only in the silhouette. A solid blue block is the largest blue area in the UI and strains the One Blue rule.</td>
    </tr>
  </tbody>
</table>

<div class="rec">
  <h3>${dropsuiteSvg(DROPSUITE_CANDIDATES[0], 20, DROPSUITE_PALETTE.dark)} Recommendation: A · Intercept D</h3>
  <p>It is the only candidate that is both a letter and the product's idea. The chamfered D gives DropSuite a custom initial that no font produces, and the cut stem with a held packet says "traffic comes in here and stops" without a single extra line. On the 16 px raster every edge lands on a whole pixel. The silhouette stays a D in white, black and blue monochrome, and it sits beside the 14 px wordmark at the same visual weight as the tab labels.</p>
  <p>Production notes for after approval: the 20 px header size is not a multiple of the 32-unit grid, so all three soften there. The approved mark will get a separately hinted 20 px drawing. The wordmark stays live text in Segoe UI Variable Display (600, 14 px, −0.015 em, 9 px from the mark); the exported master lockup will use a font stack rather than outlined Segoe glyphs, whose licence does not allow redistributing them as paths.</p>
</div>`;
