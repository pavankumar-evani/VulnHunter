"""
Static checks on the Helm chart. Helm itself is not needed (CI runs `helm lint` / `helm template`
and kubeconform in .github/workflows/helm.yml); these catch the mistakes that are cheapest to catch
here: a template that reads a value the chart does not define, an include of a helper that does
not exist, unbalanced template actions, a scenario file that sets a value the chart ignores, and
a secret value appearing where it must never be.
"""
import re
import unittest
from pathlib import Path

import yaml

CHART = Path(__file__).resolve().parent.parent / "deploy" / "helm" / "quanta"
FREE_FORM = {  # maps whose keys are chosen by the user, so their contents are not checked
    "imagePullSecrets", "serviceAccount.annotations", "serviceAccount.podLabels", "secrets.keyMap", "secrets.inline",
    "secrets.csi.parameters", "ingress.annotations", "persistence.annotations", "web.nodeSelector", "web.affinity",
    "worker.nodeSelector", "worker.affinity", "web.podAnnotations", "worker.podAnnotations",
}


def templates():
    return sorted(p for p in (CHART / "templates").rglob("*") if p.suffix in (".yaml", ".tpl", ".txt"))


def strip_comments(s):
    return re.sub(r"\{\{-?\s*/\*.*?\*/\s*-?\}\}", "", s, flags=re.S)


class ChartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.values = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))

    def test_chart_metadata(self):
        meta = yaml.safe_load((CHART / "Chart.yaml").read_text(encoding="utf-8"))
        self.assertEqual((meta["apiVersion"], meta["name"]), ("v2", "quanta"))

    def test_template_actions_balance(self):
        opener = re.compile(r"\{\{-?\s*(if|range|with|define|block)\b")
        end = re.compile(r"\{\{-?\s*end\b")
        for p in templates():
            s = strip_comments(p.read_text(encoding="utf-8"))
            self.assertEqual(len(opener.findall(s)), len(end.findall(s)), p.name)
            self.assertEqual(s.count("{{"), s.count("}}"), p.name)

    def test_every_value_a_template_reads_is_defined(self):
        missing = []
        for p in templates():
            for path in set(re.findall(r"\.Values\.([A-Za-z0-9_.]+)", p.read_text(encoding="utf-8"))):
                node, walked = self.values, []
                for part in path.split("."):
                    if not isinstance(node, dict):
                        break
                    if ".".join(walked) in FREE_FORM:
                        break
                    if part not in node:
                        missing.append(f"{p.name}: .Values.{path}")
                        break
                    node = node[part]
                    walked.append(part)
        self.assertEqual(missing, [])

    def test_every_included_helper_exists(self):
        defined = set(re.findall(r'define\s+"([^"]+)"', (CHART / "templates" / "_helpers.tpl").read_text(encoding="utf-8")))
        used = set()
        for p in templates():
            used |= set(re.findall(r'include\s+"([^"]+)"', p.read_text(encoding="utf-8")))
        self.assertEqual(sorted(used - defined), [])

    def test_ci_scenarios_only_set_known_values(self):
        def check(node, ref, path, bad):
            if not isinstance(node, dict):
                return
            for k, v in node.items():
                here = f"{path}.{k}".strip(".")
                if here in FREE_FORM:
                    continue
                if not isinstance(ref, dict) or k not in ref:
                    bad.append(here)
                    continue
                check(v, ref[k], here, bad)

        bad = []
        for f in sorted((CHART / "ci").glob("*.yaml")):
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
            check(data, self.values, "", [])
            check(data, self.values, "", bad)
        self.assertEqual(bad, [])

    def test_values_carry_no_secret_material(self):
        text = (CHART / "values.yaml").read_text(encoding="utf-8")
        self.assertEqual(self.values["secrets"]["inline"], {})
        self.assertFalse(self.values["secrets"]["allowInline"])
        self.assertNotRegex(text, r"(?i)(password|secret|token)\s*:\s*[\"']?[A-Za-z0-9+/=]{16,}")

    def test_defaults_are_safe(self):
        v = self.values
        self.assertEqual(v["secrets"]["mode"], "externalSecrets")
        self.assertEqual((v["coordination"]["lockBackend"], v["files"]["backend"]), ("db", "db"))
        self.assertFalse(v["persistence"]["enabled"])
        self.assertTrue(v["config"]["production"])

    def test_secrets_are_mounted_as_files_not_environment_values(self):
        env = (CHART / "templates" / "_helpers.tpl").read_text(encoding="utf-8")
        self.assertIn("_FILE", env)
        for name in ("QUANTA_SESSION_SECRET", "QUANTA_ENCRYPTION_KEY", "QUANTA_DATABASE_URL"):
            self.assertNotRegex(env, rf"name:\s*{name}\s*\n\s*value:")
        self.assertIn("secrets-store.csi.k8s.io", (CHART / "templates" / "_helpers.tpl").read_text(encoding="utf-8"))

    def test_pods_are_hardened(self):
        h = (CHART / "templates" / "_helpers.tpl").read_text(encoding="utf-8")
        for needle in ("runAsNonRoot: true", "allowPrivilegeEscalation: false", 'drop: ["ALL"]', "RuntimeDefault"):
            self.assertIn(needle, h)
        self.assertIn("automountServiceAccountToken: false", (CHART / "templates" / "serviceaccount.yaml").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
