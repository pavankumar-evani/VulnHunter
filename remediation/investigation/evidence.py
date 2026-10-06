"""
The evidence ledger: the one rule every investigation report follows.

A statement in a report is allowed only if it cites at least one evidence item the report itself lists (E1, E2, ...). Each item names where it came
from (a stored alert, a stored investigation, a reputation lookup, a SIEM search, an access record, a finding, a count over stored data) and when.
A statement that cites nothing, or cites a reference the ledger does not hold, is dropped and counted; the report says how many it dropped, so the
reader knows the text was filtered rather than complete. A caller may ask for an unevidenced statement to be kept and marked "not evidenced".

Nothing here writes prose. It only decides which sentences may stand.
"""
import datetime


class Ledger:
    def __init__(self):
        self.items = []
        self._by_key = {}
        self._by_ref = {}
        self.dropped = []

    def add(self, kind, source, detail, at=None, key=None, data=None):
        """Registers one piece of evidence and returns its reference. The same (kind, key) is registered once."""
        k = (kind, key if key is not None else (source, detail))
        if k in self._by_key:
            return self._by_key[k]
        ref = f"E{len(self.items) + 1}"
        item = {"ref": ref, "kind": kind, "source": source, "detail": detail, "at": at}
        if data is not None:
            item["data"] = data
        self.items.append(item)
        self._by_key[k] = ref
        self._by_ref[ref] = item
        return ref

    def has(self, ref):
        return ref in self._by_ref

    def get(self, ref):
        return self._by_ref.get(ref)

    def claim(self, text, refs, keep_unevidenced=False):
        """-> {"text", "evidence": [refs]} or None. A claim with no valid reference is dropped (and recorded), or kept as "not evidenced"."""
        good = [r for r in dict.fromkeys(refs or []) if r in self._by_ref]
        if good and text:
            return {"text": text, "evidence": good}
        self.dropped.append(text)
        if keep_unevidenced and text:
            return {"text": text, "evidence": [], "status": "not evidenced"}
        return None

    def add_claim(self, out, text, refs, keep_unevidenced=False):
        c = self.claim(text, refs, keep_unevidenced)
        if c is not None:
            out.append(c)
        return c

    def kinds(self):
        return sorted({i["kind"] for i in self.items})

    def export(self):
        return list(self.items)


def now_iso(now=None):
    return (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse(ts):
    try:
        return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        return None
