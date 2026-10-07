"""Scenario packs: every technique exists in the catalog, every scenario has SPL and Sigma (or an honest not-expressible), queries are read-only, rendering is honest, coverage of the requested themes."""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402

from remediation.connectors import siem_search_connector as siem  # noqa: E402
from remediation.hunting.knowledge import catalog, safe_query, scenarios  # noqa: E402

REQUIRED_THEMES = {
    "phishing": ["phish-credential-harvest", "phish-malicious-attachment-macro", "phish-container-lnk-onenote-iso", "phish-qr-code", "phish-mfa-fatigue-aitm", "phish-thread-hijack",
                 "phish-bec-payment-fraud", "phish-mailbox-rules-persistence", "phish-oauth-consent-abuse"],
    "social": ["social-helpdesk-impersonation-vishing", "social-callback-phishing", "social-deepfake-approval", "social-sim-swap"],
    "insider": ["insider-staging-exfil-personal-cloud", "insider-mass-download", "insider-privilege-abuse", "insider-off-hours-access", "insider-departing-employee", "insider-source-code-theft", "insider-sabotage"],
    "drive-by": ["driveby-browser-exploit", "driveby-malvertising-seo", "driveby-fake-updater", "driveby-clickfix-paste-and-run"],
    "cloud": ["cloud-subscription-tenant-abuse", "cloud-unused-region-activity", "cloud-account-user-key-creation", "cloud-crypto-mining-compute", "cloud-leaked-key-new-geography", "cloud-impossible-travel",
              "cloud-overprivileged-role-assumption", "cloud-snapshot-bucket-exposure", "cloud-serverless-persistence", "cloud-billing-spike", "cloud-disabled-logging"],
    "identity": ["identity-kerberoasting", "identity-dcsync", "identity-golden-silver-ticket", "identity-pass-the-hash", "identity-pass-the-ticket", "identity-shadow-admin"],
    "system": ["sys-new-service-install", "sys-scheduled-task-persistence", "sys-wmi-event-subscription", "sys-registry-run-keys-persistence", "sys-vulnerable-driver-byovd", "sys-lolbin-proxy-execution",
               "sys-uncommon-parent-child", "sys-unsigned-binary-odd-path", "sys-powershell-obfuscation", "sys-dll-sideloading"],
    "user": ["user-rare-logon-new-device", "user-first-seen-admin-tool", "user-abnormal-command-history"],
    "network": ["net-beaconing", "net-dns-tunnelling", "net-rare-domains-and-links", "net-newly-registered-domains", "net-dga-domains", "net-tls-rare-asn", "net-exfiltration-volume"],
    "ransomware": ["ransom-backup-tamper-precursors", "ransom-mass-encryption", "ransom-lateral-staging"],
    "supply": ["supply-poisoned-package", "supply-ci-token-abuse"],
    "ai": ["ai-prompt-injection-tool-misuse", "ai-model-dataset-poisoning", "ai-model-extraction-theft", "ai-llmjacking-cost-anomaly", "ai-malicious-model-pickle", "ai-vector-store-poisoning", "ai-mcp-tool-abuse"],
    "malware": ["malware-infostealer", "malware-c2-framework-implant", "malware-webshell", "malware-fileless-reflective-loading", "malware-rootkit-bootkit", "malware-wiper", "malware-loader-dropper-rat"],
}


class ScenarioPackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        catalog.reload()
        scenarios.reload()
        cls.c = catalog.get()
        cls.all = scenarios.load()

    def test_the_catalog_is_present_for_these_tests_to_mean_anything(self):
        self.assertTrue(self.c.available)

    def test_no_problems_found_by_the_validator(self):
        self.assertEqual(scenarios.problems(), [])

    def test_every_technique_id_exists_in_the_catalog(self):
        for s in self.all:
            for t in s["techniques"]:
                self.assertTrue(self.c.exists(t), f"{s['id']}: {t}")
            for lead in s["leads"]:
                self.assertTrue(self.c.exists(lead["technique"]), f"{s['id']} lead {lead['name']}: {lead['technique']}")

    def test_ids_are_unique_and_every_requested_theme_is_covered(self):
        ids = [s["id"] for s in self.all]
        self.assertEqual(len(ids), len(set(ids)))
        for theme, want in REQUIRED_THEMES.items():
            for sid in want:
                self.assertIn(sid, ids, f"{theme}: missing {sid}")
        self.assertGreaterEqual(len(self.all), 85)
        self.assertEqual({s["category"] for s in self.all}, set(scenarios.CATEGORIES))

    def test_every_scenario_has_spl_and_a_sigma_rule_or_an_honest_reason(self):
        for s in self.all:
            ok = False
            for lead in s["leads"]:
                r = scenarios.render_lead(lead, s)
                spl, sig = r["languages"]["splunk-spl"], r["languages"]["sigma"]
                self.assertIn(sig["status"], ("provided", "not-expressible"), f"{s['id']}/{lead['name']}: Sigma must be given or honestly not expressible")
                if sig["status"] == "not-expressible":
                    self.assertTrue(sig["reason"])
                if spl["status"] == "provided" and sig["status"] in ("provided", "not-expressible"):
                    ok = True
            self.assertTrue(ok, s["id"])

    def test_most_scenarios_have_a_real_sigma_rule_and_kql_and_eql(self):
        with_sigma = sum(1 for s in self.all if any(scenarios.render_lead(ld, s)["languages"]["sigma"]["status"] == "provided" for ld in s["leads"]))
        with_kql = sum(1 for s in self.all if any(scenarios.render_lead(ld, s)["languages"]["kql"]["status"] == "provided" for ld in s["leads"]))
        with_eql = sum(1 for s in self.all if any(scenarios.render_lead(ld, s)["languages"]["eql"]["status"] == "provided" for ld in s["leads"]))
        self.assertGreaterEqual(with_sigma, int(len(self.all) * 0.95))
        self.assertGreaterEqual(with_kql, int(len(self.all) * 0.95))
        self.assertGreaterEqual(with_eql, int(len(self.all) * 0.95))

    def test_not_expressible_is_stated_not_guessed(self):
        found = 0
        for s in self.all:
            for lead in s["leads"]:
                if lead.get("selection"):
                    continue
                r = scenarios.render_lead(lead, s)
                for lang, v in r["languages"].items():
                    self.assertIn(v["status"], ("provided", "not-expressible", "not-provided"))
                    if v["status"] != "provided":
                        found += 1
                        self.assertTrue(v["reason"], f"{s['id']} {lang}")
                        self.assertNotIn("query", v)       # nothing is filled in with a guess
        self.assertGreater(found, 10)
        beacon = scenarios.render_lead(scenarios.get("net-beaconing")["leads"][0], scenarios.get("net-beaconing"))
        self.assertEqual(beacon["languages"]["sigma"]["status"], "not-expressible")
        self.assertIn("statistic", beacon["languages"]["sigma"]["reason"])

    def test_every_spl_query_passes_the_read_only_validator_and_the_safe_gate(self):
        n = 0
        for s in self.all:
            for lead in s["leads"]:
                spl = scenarios.render_lead(lead, s)["languages"]["splunk-spl"]
                if spl["status"] == "provided":
                    n += 1
                    siem.check_query(spl["query"])
                    self.assertTrue(safe_query.check("splunk-spl", spl["query"])["ok"], (s["id"], lead["name"]))
        self.assertGreater(n, 150)

    def test_every_generated_sigma_is_parseable_and_tagged(self):
        for s in self.all:
            for lead in s["leads"]:
                sg = scenarios.render_lead(lead, s)["languages"]["sigma"]
                if sg["status"] == "provided":
                    doc = yaml.safe_load(sg["query"])
                    self.assertIn("condition", doc["detection"])
                    self.assertTrue(doc["tags"])
                    self.assertTrue(safe_query.check("sigma", sg["query"])["ok"], s["id"])

    def test_eql_rendering(self):
        self.assertEqual(scenarios.to_eql({"Image|endswith": ["\\a.exe", "\\b.exe"], "EventID": 1}), 'any where Image like~ ("*\\\\a.exe", "*\\\\b.exe") and EventID == 1')
        with self.assertRaises(ValueError):
            scenarios.to_eql({"A|re": "x"})
        with self.assertRaises(ValueError):
            scenarios.to_eql({})

    def test_playbooks_exist_and_each_has_steps_and_approval_flags(self):
        pb = scenarios.playbooks()
        self.assertGreaterEqual(len(pb), 10)
        for s in self.all:
            self.assertIn(s["playbook"], pb)
        for p in pb.values():
            self.assertTrue(p["steps"])
            self.assertTrue(all("needs_approval" in st for st in p["steps"]))

    def test_each_scenario_has_expected_malicious_benign_tuning_and_a_diamond(self):
        for s in self.all:
            for k in ("malicious", "benign", "tuning", "response"):
                self.assertTrue(s[k], f"{s['id']} {k}")
            for k in ("capability", "infrastructure", "victim"):
                self.assertTrue(s["diamond"][k])
            self.assertTrue(s["data_sources"])
            self.assertTrue(set(s["data_sources"]) <= set(scenarios.DATA_CLASSES))

    def test_ai_scenarios_use_atlas_and_system_scenarios_use_attack(self):
        for sid in REQUIRED_THEMES["ai"]:
            s = scenarios.get(sid)
            self.assertTrue(all(t.startswith("AML.") for t in s["techniques"]), sid)
        kinds = {self.c.technique(t, detail=False)["framework"] for s in self.all for t in s["techniques"]}
        self.assertEqual(kinds, {"enterprise", "atlas", "ics", "mobile"})

    def test_a_broken_scenario_is_caught(self):
        bad = {"id": "x", "title": "t", "category": "cloud", "hypothesis": "no scope here", "techniques": ["T0000"], "kill_chain": ["nope"], "diamond": {}, "data_sources": ["nothing"],
               "leads": [{"name": "l", "technique": "T0000", "spl": "search a | outputlookup x"}], "malicious": ["a"], "benign": ["b"], "tuning": ["c"], "severity": "high", "priority": "high", "playbook": "pb-none", "response": ["r"]}
        errs = scenarios.validate(bad, self.c, set(scenarios.playbooks()))
        text = " ".join(errs)
        for needle in ("not in the catalog", "unknown kill-chain", "unknown data class", "refused by the read-only validator", "playbook pb-none", "hypothesis must start"):
            self.assertIn(needle, text)


class SafeQueryTests(unittest.TestCase):
    def test_spl_reuses_the_siem_validator(self):
        self.assertTrue(safe_query.check("splunk-spl", "search index=a | stats count by host")["ok"])
        for bad in ("index=a | stats count", "search a | outputlookup x", "search a | script foo", "search `macro`", "search a | delete"):
            self.assertFalse(safe_query.check("splunk-spl", bad)["ok"], bad)

    def test_kql_eql_sigma(self):
        self.assertTrue(safe_query.check("kql", "SigninLogs | where ResultType == 0 | take 5")["ok"])
        for bad in (".drop table X", "SigninLogs | evaluate python()", "externaldata(x:string) [h@'https://x']", "cluster('a').database('b').T"):
            self.assertFalse(safe_query.check("kql", bad)["ok"], bad)
        self.assertTrue(safe_query.check("eql", "process where process.name == \"cmd.exe\" | head 5")["ok"])
        self.assertFalse(safe_query.check("eql", "DROP INDEX")["ok"])
        self.assertFalse(safe_query.check("eql", "process where true | evil")["ok"])
        self.assertTrue(safe_query.check("sigma", "title: t\nlogsource: {category: x}\ndetection:\n  selection: {a: 1}\n  condition: selection\n")["ok"])
        self.assertFalse(safe_query.check("sigma", "title: t\n")["ok"])
        self.assertFalse(safe_query.check("klingon", "x")["ok"])
        self.assertFalse(safe_query.check("kql", "")["ok"])
        self.assertFalse(safe_query.check("kql", "a" * 7000)["ok"])


if __name__ == "__main__":
    unittest.main()
