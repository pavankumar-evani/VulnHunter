// Every page that lists findings opens its detail through here. The detail is now the side drawer in findingDrawer.js (overview, how to fix,
// context, ownership) instead of the old modal; the function name and the argument (a finding object) are unchanged, so no caller needed to change.
import { openFindingDrawer } from "./findingDrawer.js";

export function openFindingDetail(f, options) {
  return openFindingDrawer(f, options);
}
