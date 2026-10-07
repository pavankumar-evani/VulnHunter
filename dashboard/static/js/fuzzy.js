// Fuzzy matching for the command palette. Pure (no DOM), so it is tested under Node (tests/test_ui_kit_js.py).
// A query is split on spaces; every word must match as an in-order subsequence of the text. Matches score higher when the
// letters are consecutive, start a word, or start the text, and lower the later and more spread out they are.

const SEP = /[\s\-_/:.,()]/;

// Score one word against one text. Returns null (no match) or { score, indices }.
export function fuzzyWord(word, text, { subsequence = true } = {}) {
  const w = word.toLowerCase();
  const t = text.toLowerCase();
  if (!w) return { score: 0, indices: [] };
  // Fast path: a plain substring is the best kind of match; prefer one at a word boundary.
  const at = t.indexOf(w);
  if (at !== -1) {
    const boundary = at === 0 || SEP.test(t[at - 1]);
    const indices = Array.from({ length: w.length }, (_, i) => at + i);
    return { score: 100 + w.length * 4 + (boundary ? 40 : 0) + (at === 0 ? 20 : 0) - Math.min(at, 30) * 0.5, indices };
  }
  if (!subsequence || w.length < 2) return null;
  // Greedy subsequence with bonuses.
  const indices = [];
  let ti = 0;
  let score = 0;
  let prev = -2;
  for (let wi = 0; wi < w.length; wi += 1) {
    let found = -1;
    // prefer a word-start position for this letter when one is close
    for (let k = ti; k < t.length; k += 1) {
      if (t[k] !== w[wi]) continue;
      const good = k === 0 || SEP.test(t[k - 1]) || k === prev + 1;
      if (found === -1) found = k;                       // the first occurrence ...
      if (good && k - found <= 8) { found = k; break; }  // ... unless a word start or adjacent one is close behind it
      if (k - found > 8) break;
    }
    if (found === -1) return null;
    score += 10;
    if (found === prev + 1) score += 15;
    if (found === 0 || SEP.test(t[found - 1])) score += 12;
    score -= Math.min(found - (prev + 1), 10) * 0.4;
    indices.push(found);
    prev = found;
    ti = found + 1;
  }
  // Scattered letters are not a match: the letters must sit close together (within 3x the word) or be the initials of words
  // ("rq" -> Remediation Queue). Otherwise "hunt" would match anything containing an h, a u, an n and a t somewhere.
  const span = indices[indices.length - 1] - indices[0] + 1;
  const initials = indices.filter((k) => k === 0 || SEP.test(t[k - 1])).length;
  if (span > w.length * 3 && initials < w.length - 1) return null;
  return { score, indices };
}

// Score a whole query against a text. Returns null or { score, indices } (indices merged and sorted).
export function fuzzyScore(query, text, opts) {
  const words = String(query || "").trim().split(/\s+/).filter(Boolean);
  if (!words.length) return { score: 0, indices: [] };
  let score = 0;
  const all = new Set();
  for (const word of words) {
    const m = fuzzyWord(word, String(text || ""), opts);
    if (!m) return null;
    score += m.score;
    m.indices.forEach((i) => all.add(i));
  }
  // shorter texts win ties: "Hunting" beats "Hunting and SOC triage settings" for "hunt"
  score -= Math.min(String(text).length, 80) * 0.05;
  return { score, indices: [...all].sort((a, b) => a - b) };
}

// Rank items. `fields(item)` returns [primaryText, ...secondaryTexts]; the primary text counts in full, the others at a discount.
// Returns [{ item, score, indices }] best first, only items that match. With an empty query every item is returned in its original order.
export function rank(items, query, fields = (i) => [i.label], limit = 50) {
  const q = String(query || "").trim();
  if (!q) return items.slice(0, limit).map((item) => ({ item, score: 0, indices: [] }));
  const out = [];
  for (const item of items) {
    const [primary, ...rest] = fields(item);
    let best = null;
    const p = fuzzyScore(q, primary || "");
    if (p) best = { item, score: p.score, indices: p.indices };
    for (const text of rest) {
      const s = fuzzyScore(q, text || "", { subsequence: false }); // secondary text: whole-word/substring matches only
      if (s && (!best || s.score * 0.6 > best.score)) best = { item, score: s.score * 0.6, indices: best ? best.indices : [] };
    }
    if (best) out.push(best);
  }
  out.sort((a, b) => b.score - a.score);
  return out.slice(0, limit);
}

// HTML with matched letters wrapped in <mark>; the text is escaped first, so it is safe to insert.
export function highlight(text, indices) {
  const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  const s = String(text || "");
  if (!indices || !indices.length) return esc(s);
  const set = new Set(indices);
  let out = "";
  let open = false;
  for (let i = 0; i < s.length; i += 1) {
    const hit = set.has(i);
    if (hit && !open) { out += "<mark>"; open = true; }
    if (!hit && open) { out += "</mark>"; open = false; }
    out += esc(s[i]);
  }
  if (open) out += "</mark>";
  return out;
}
