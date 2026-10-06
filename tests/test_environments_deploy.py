"""Static checks on the per-environment Helm overlays, Dockerfile, compose overrides and release workflows.
Helm and Docker are not installed here and the workflows have never run: these only read the files."""
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CHART = ROOT / "deploy" / "helm" / "quanta"
WF = ROOT / ".github" / "workflows"


def load(p):
    return yaml.safe_load(Path(p).read_text(encoding="utf-8"))


def known_keys(node, ref, path, bad):
    free = {"secrets.keyMap", "secrets.inline", "ingress.annotations"}
    if not isinstance(node, dict) or path in free:
        return
    for k, v in node.items():
        here = f"{path}.{k}".strip(".")
        if not isinstance(ref, dict) or k not in ref:
            bad.append(here)
            continue
        known_keys(v, ref[k], here, bad)


class OverlayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = load(CHART / "values.yaml")
        cls.o = {e: load(CHART / f"values-{e}.yaml") for e in ("dev", "test", "prod")}

    def test_each_overlay_sets_its_environment_and_known_keys_only(self):
        for e, d in self.o.items():
            self.assertEqual(d["config"]["environment"], e)
            bad = []
            known_keys(d, self.base, "", bad)
            self.assertEqual(bad, [], e)

    def test_prod_rules(self):
        p = self.o["prod"]
        self.assertGreaterEqual(p["web"]["replicas"], 2)
        self.assertTrue(p["podDisruptionBudget"]["enabled"])
        self.assertTrue(p["networkPolicy"]["enabled"])
        self.assertTrue(p["config"]["production"])
        self.assertIs(p["config"]["allowSimulation"], False)
        self.assertIn("example.com", p["ingress"]["host"])

    def test_no_environment_allows_simulation_in_a_pod_overlay_by_default_for_prod_and_test_networkpolicy(self):
        self.assertTrue(self.o["test"]["networkPolicy"]["enabled"])
        self.assertTrue(self.o["test"]["config"]["production"])
        self.assertFalse(self.o["dev"]["config"]["production"])

    def test_base_defaults_never_allow_simulation(self):
        self.assertIs(self.base["config"]["allowSimulation"], False)
        self.assertEqual(self.base["config"]["environment"], "prod")   # the safe default: no overlay means production, simulation off

    def test_overlays_hold_no_secret_material(self):
        for e in self.o:
            t = (CHART / f"values-{e}.yaml").read_text(encoding="utf-8")
            self.assertNotRegex(t, r"(?i)(password|secret|token|key)\s*:\s*[\"']?[A-Za-z0-9+/=]{20,}")

    def test_chart_renders_quanta_env(self):
        h = (CHART / "templates" / "_helpers.tpl").read_text(encoding="utf-8")
        self.assertRegex(h, r"name: QUANTA_ENV\s*\n\s*value: \{\{ \.Values\.config\.environment")
        self.assertRegex(h, r"name: QUANTA_ALLOW_SIMULATION\s*\n\s*value: \{\{ \.Values\.config\.allowSimulation")


class ImageAndComposeTests(unittest.TestCase):
    def test_dockerfile_build_args_and_label(self):
        t = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        for a in ("VERSION", "BUILD_SHA", "BUILD_TIME"):
            self.assertRegex(t, rf"(?m)^ARG {a}=")
        self.assertIn("QUANTA_BUILD_SHA=${BUILD_SHA}", t)
        self.assertIn("QUANTA_BUILD_TIME=${BUILD_TIME}", t)
        self.assertIn("org.opencontainers.image.revision", t)
        self.assertNotRegex(t, r"(?m)^ENV[^\n]*QUANTA_ENV")  # the environment is configuration, never baked in

    def test_compose_overrides(self):
        for e in ("dev", "test"):
            d = load(ROOT / f"docker-compose.{e}.yml")
            self.assertEqual(d["services"]["quanta"]["environment"]["QUANTA_ENV"], e)
            self.assertEqual(d["services"]["quanta"]["environment"]["QUANTA_ALLOW_SIMULATION"], "true")
            env = (ROOT / f".env.{e}.example").read_text(encoding="utf-8")
            self.assertIn(f"QUANTA_ENV={e}", env)
        base = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertNotIn("QUANTA_ALLOW_SIMULATION", base)


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wf = {p.name: load(p) for p in sorted(WF.glob("*.yml"))}

    def jobs(self, name):
        return self.wf[name]["jobs"]

    def test_every_workflow_parses_with_explicit_permissions(self):
        for name, w in self.wf.items():
            self.assertIn("permissions", w, f"{name}: top-level permissions must be explicit")
            self.assertIn("jobs", w)

    def test_release_chain_and_gates(self):
        j = self.jobs("release.yml")
        self.assertEqual(j["deploy-prod"]["environment"], "prod")
        self.assertIn("deploy-test", j["deploy-prod"]["needs"])
        self.assertIn("deploy-dev", j["deploy-test"]["needs"])
        self.assertEqual(j["deploy-test"]["environment"], "test")
        self.assertEqual(j["deploy-dev"]["environment"], "dev")
        self.assertIn("build", j["deploy-dev"]["needs"])
        self.assertIn("verify", j["build"]["needs"])

    def test_deploy_jobs_are_guarded(self):
        for name in ("release.yml", "rollback.yml"):
            for jn, job in self.jobs(name).items():
                if jn.startswith("deploy") or jn == "rollback":
                    self.assertIn("vars.DEPLOY_ENABLED == 'true'", job["if"], f"{name}:{jn}")

    def test_build_permissions_and_attestations(self):
        b = self.jobs("release.yml")["build"]
        self.assertEqual(b["permissions"], {"contents": "read", "packages": "write", "id-token": "write", "attestations": "write"})
        text = (WF / "release.yml").read_text(encoding="utf-8")
        self.assertRegex(text, r"sbom:\s*true")
        self.assertRegex(text, r"provenance:")
        self.assertEqual(text.count("docker/build-push-action"), 1)
        for a in ("VERSION=", "BUILD_SHA=", "BUILD_TIME="):
            self.assertIn(a, text)

    def test_deploys_use_atomic_helm_and_per_environment_kubeconfig(self):
        text = (WF / "release.yml").read_text(encoding="utf-8")
        self.assertEqual(text.count("helm upgrade --install"), 3)
        self.assertEqual(text.count("--atomic --wait"), 3)
        for e in ("dev", "test", "prod"):
            self.assertIn(f"values-{e}.yaml", text)
        self.assertIn("secrets.KUBE_CONFIG", text)
        self.assertIn("helm get values", text)
        self.assertIn("helm history", text)
        self.assertIn("/api/status", text)
        self.assertIn("rollback", (WF / "rollback.yml").read_text(encoding="utf-8"))
        self.assertIn("helm rollback", (WF / "rollback.yml").read_text(encoding="utf-8"))

    def test_no_event_data_interpolated_into_run_scripts(self):
        bad = re.compile(r"\$\{\{\s*(github\.event\.|inputs\.|github\.head_ref)")
        for name, w in self.wf.items():
            for jn, job in w["jobs"].items():
                for s in job.get("steps", []):
                    if "run" in s:
                        self.assertIsNone(bad.search(s["run"]), f"{name}:{jn}: untrusted value interpolated into a run script (use env:)")

    def test_actions_are_pinned_by_tag(self):
        for name, w in self.wf.items():
            for jn, job in w["jobs"].items():
                for s in job.get("steps", []):
                    if "uses" in s:
                        self.assertRegex(s["uses"], r"@v?\d", f"{name}:{jn}: {s['uses']} must be pinned")


if __name__ == "__main__":
    unittest.main()
