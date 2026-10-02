"""
Unified diffs: producing one for a reviewer, and applying one proposed by a person or a model to a file's current content.

Applying is strict on purpose. A hunk is applied only where its context and removed lines match the file exactly (searching a few lines either side of
where the hunk says it should be, because line numbers drift). If it does not match, the patch is refused with the hunk that failed: a fix that does not
fit the current code is a fix a reviewer has to see, not one to apply approximately.
"""
import difflib
import re

SEARCH = 40  # how many lines either side of the stated position a hunk may be found at
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class PatchRefused(ValueError):
    pass


def unified(old, new, path):
    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True), f"a/{path}", f"b/{path}", n=3))


def stats(diff):
    add = sum(1 for ln in diff.split("\n") if ln.startswith("+") and not ln.startswith("+++"))
    rem = sum(1 for ln in diff.split("\n") if ln.startswith("-") and not ln.startswith("---"))
    return {"added": add, "removed": rem}


def _hunks(diff):
    hunks, cur = [], None
    for raw in diff.replace("\r\n", "\n").rstrip("\n").split("\n"):
        if raw.startswith(("--- ", "+++ ", "diff ", "index ", "new file", "deleted file", "similarity", "rename ")) and cur is None:
            continue
        m = _HUNK.match(raw)
        if m:
            cur = {"old_start": int(m.group(1)), "lines": []}
            hunks.append(cur)
        elif cur is not None:
            if raw.startswith("\\"):
                continue
            if raw[:1] in (" ", "+", "-"):
                cur["lines"].append((raw[0], raw[1:]))
            elif raw == "":
                cur["lines"].append((" ", ""))
    return hunks


def apply(old_text, diff):
    """The patched text. Raises PatchRefused when the diff is empty, malformed or does not fit."""
    hunks = _hunks(diff)
    if not hunks:
        raise PatchRefused("The patch has no hunks")
    ends_nl = old_text.endswith("\n")
    lines = old_text.split("\n")
    if ends_nl:
        lines.pop()
    offset = 0
    for n, h in enumerate(hunks, 1):
        before = [t for k, t in h["lines"] if k in (" ", "-")]
        after = [t for k, t in h["lines"] if k in (" ", "+")]
        if not any(k in ("+", "-") for k, _ in h["lines"]):
            raise PatchRefused(f"Hunk {n} changes nothing")
        want = max(h["old_start"] - 1 + offset, 0)
        found = None
        for delta in sorted(range(-SEARCH, SEARCH + 1), key=abs):
            pos = want + delta
            if pos >= 0 and lines[pos:pos + len(before)] == before:
                found = pos
                break
        if found is None:
            raise PatchRefused(f"Hunk {n} (around line {h['old_start']}) does not match the file as it is now")
        lines[found:found + len(before)] = after
        offset += len(after) - len(before)
    return "\n".join(lines) + ("\n" if ends_nl or not old_text else "")
