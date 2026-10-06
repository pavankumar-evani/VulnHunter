"""Security Posture Review: one deterministic assessment of the recorded estate and of this Quanta deployment against ten frameworks.

Each framework is a module in this package exposing `FRAMEWORK` (id, title, summary, areas, refs) and `run(ctx) -> list[check]` (see model.py). The engine
(engine.py) runs them all against one shared Context, scores each framework from the checks it could observe, and ranks the open gaps into an action list
with the exact setting that closes each one. Nothing here changes anything: it reads what Quanta already holds and advises.
"""
import importlib

# (module name inside this package, in the order the page shows them)
FRAMEWORK_MODULES = (
    "zero_trust", "secure_by_design", "threat_modelling", "defence_in_depth", "architecture",
    "sdlc", "aidlc", "supply_chain", "ai_supply_chain", "open_source",
)


def load_frameworks():
    """The framework modules that exist, in display order. A module that is missing or fails to import is reported, not hidden."""
    found, problems = [], {}
    for name in FRAMEWORK_MODULES:
        try:
            found.append(importlib.import_module(f"remediation.posture.{name}"))
        except ModuleNotFoundError as exc:
            if exc.name == f"remediation.posture.{name}":
                problems[name] = "not installed"
            else:
                problems[name] = f"import failed: {exc}"[:200]
        except Exception as exc:  # noqa: BLE001
            problems[name] = f"import failed: {type(exc).__name__}: {exc}"[:200]
    return found, problems
