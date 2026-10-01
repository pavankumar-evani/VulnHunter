// Opens the full finding-detail modal from just a finding ID. The ownership pages list
// findings by a few summary fields, but the detail modal wants the whole scored finding
// - this fetches the live queue once (the same /api/queue every other page uses) and
// caches it briefly so repeated clicks don't each re-download ~9,000 findings.
import { api } from "./api.js";
import { flash } from "./dom.js";
import { openFindingDetail } from "./findingDetail.js";

const TTL_MS = 60_000;
let cache = { at: 0, promise: null };

function queueById() {
  if (!cache.promise || Date.now() - cache.at > TTL_MS) {
    cache = { at: Date.now(), promise: api.queue().then((q) => new Map(q.findings.map((f) => [f.id, f]))) };
  }
  return cache.promise;
}

export async function openFindingById(findingId) {
  try {
    const finding = (await queueById()).get(findingId);
    if (!finding) {
      flash(`${findingId} is no longer in the live queue.`, "error");
      return;
    }
    openFindingDetail(finding);
  } catch (err) {
    cache = { at: 0, promise: null };
    flash(err.message, "error");
  }
}
