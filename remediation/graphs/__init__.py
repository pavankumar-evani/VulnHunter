"""Per-module relationship graphs (see schema.py for the shape). Each builder module exposes build(engine=None, **context) -> dict."""
import importlib

MODULES = ("soc", "appsec", "devsecops", "infra", "ai", "remediation", "grc", "admin")


def build(module, **context):
    if module not in MODULES:
        raise KeyError(module)
    return importlib.import_module(f"remediation.graphs.{module}").build(**context)
