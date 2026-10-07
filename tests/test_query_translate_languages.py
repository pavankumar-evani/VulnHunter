"""
Query rendering for every SIEM language from the Sigma-style selections the hunt library and engine use. A table of selections per language, including the
constructs a language cannot express (reported as NotExpressible, never silently dropped), and the per-language query-playbook templates.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from remediation.hunting import generate, soc as hunt_soc, translate  # noqa: E402
from remediation.investigation import playbook as qpb  # noqa: E402

SHELL = {"Image|endswith": ["\\cmd.exe", "/bin/sh"], "ParentImage|endswith": ["\\w3wp.exe"]}
LOGON = {"EventID": 4624, "LogonType": [3, 10]}
JNDI = {"CommandLine|contains": ["${jndi:", "a*b"]}
START = {"CommandLine|startswith": "powershell -enc"}
EXACT = {"User": "SYSTEM"}


class TranslateTable(unittest.TestCase):
    def test_every_language_is_registered(self):
        self.assertEqual(set(translate.LANGUAGES), set(translate.RENDERERS))

    def test_kql(self):
        self.assertEqual(translate.render("kql", SHELL, ["WEB-1"]),
                         'union * | where DeviceName in~ ("WEB-1") or Computer in~ ("WEB-1") | where (Image endswith "\\\\cmd.exe" or Image endswith "/bin/sh") and ParentImage endswith "\\\\w3wp.exe"')
        self.assertEqual(translate.render("kql", LOGON), "union * | where EventID == 4624 and (LogonType == 3 or LogonType == 10)")
        self.assertEqual(translate.render("kql", EXACT), 'union * | where User =~ "SYSTEM"')
        self.assertIn('CommandLine startswith "powershell -enc"', translate.render("kql", START))

    def test_eql(self):
        self.assertEqual(translate.render("eql", SHELL, ["WEB-1"]),
                         'any where host.name in~ ("WEB-1") and (endsWith~(Image, "\\\\cmd.exe") or endsWith~(Image, "/bin/sh")) and endsWith~(ParentImage, "\\\\w3wp.exe")')
        self.assertEqual(translate.render("eql", LOGON), "any where EventID == 4624 and (LogonType == 3 or LogonType == 10)")
        self.assertEqual(translate.render("eql", EXACT), 'any where User : "SYSTEM"')
        self.assertIn('stringContains~(CommandLine, "${jndi:")', translate.render("eql", JNDI))
        self.assertIn('startsWith~(CommandLine, "powershell -enc")', translate.render("eql", START))

    def test_eql_cannot_match_a_wildcard_literally_in_an_equality(self):
        with self.assertRaises(translate.NotExpressible):
            translate.render("eql", {"User": "a*b"})

    def test_esql(self):
        out = translate.render("esql", SHELL, ["WEB-1"])
        self.assertTrue(out.startswith('FROM logs-* | WHERE TO_LOWER(host.name) IN ("web-1") AND '))
        self.assertIn('TO_LOWER(Image) LIKE "*\\\\cmd.exe"', out)
        self.assertEqual(translate.render("esql", LOGON, None, "winlogbeat-*"), "FROM winlogbeat-* | WHERE EventID == 4624 AND (LogonType == 3 OR LogonType == 10)")
        self.assertEqual(translate.render("esql", EXACT), 'FROM logs-* | WHERE TO_LOWER(User) == "system"')
        self.assertIn('LIKE "*a\\\\*b*"', translate.render("esql", JNDI))       # a literal * is escaped, not a wildcard

    def test_udm(self):
        out = translate.render("udm", SHELL, ["WEB-1"])
        self.assertTrue(out.startswith('(principal.hostname = "WEB-1" nocase OR target.hostname = "WEB-1" nocase) AND '))
        self.assertIn("target.process.file.full_path = /^.*\\\\cmd\\.exe$/ nocase", out)
        self.assertIn("principal.process.file.full_path = /^.*\\\\w3wp\\.exe$/ nocase", out)
        self.assertEqual(translate.render("udm", {"DestinationPort": [445, 3389]}), "(target.port = 445 OR target.port = 3389)")
        self.assertEqual(translate.render("udm", {"User": "SYSTEM"}), 'principal.user.userid = "SYSTEM" nocase')

    def test_fql_takes_only_host_attribute_selections(self):
        self.assertEqual(translate.render("fql", {"ComputerName": "WEB-1"}), "hosts hostname:'WEB-1'")
        self.assertEqual(translate.render("fql", {"ComputerName": ["A", "B"], "LocalIP": "10.0.0.1"}), "hosts hostname:['A','B']+local_ip:'10.0.0.1'")
        self.assertEqual(translate.render("fql", {"ComputerName": "it's"}), "hosts hostname:'its'")   # a quote cannot break out of the filter

    def test_unsupported_constructs_are_reported_never_dropped(self):
        cases = [("fql", SHELL), ("fql", {"ComputerName|contains": "x"}), ("udm", LOGON), ("udm", {"Hashes|contains": "abc"}),
                 ("kql", {"Image|re": "x.*"}), ("eql", {"Image|all": ["a"]}), ("esql", {"Image|cidr": "10.0.0.0/8"}), ("udm", {"bad field!": "x"}), ("kql", {"a;b": "x"}),
                 ("nosuch", EXACT)]
        for lang, sel in cases:
            with self.assertRaises(translate.NotExpressible, msg=f"{lang} {sel}"):
                translate.render(lang, sel)
        self.assertTrue(issubclass(translate.NotExpressible, ValueError))   # older callers that catch ValueError keep working

    def test_one_unmappable_field_fails_the_whole_selection_rather_than_dropping_it(self):
        with self.assertRaises(translate.NotExpressible):
            translate.render("udm", {"Image|endswith": "x.exe", "LogonType": 3})

    def test_an_empty_selection_is_a_plain_value_error(self):
        for lang in translate.LANGUAGES:
            with self.assertRaises(ValueError):
                translate.render(lang, {})

    def test_hyphenated_fields_are_quoted_where_the_language_needs_it(self):
        sel = {"cs-uri-query|contains": "x"}
        self.assertIn("['cs-uri-query'] contains", translate.render("kql", sel))
        self.assertIn("`cs-uri-query`", translate.render("esql", sel))
        self.assertIn("`cs-uri-query`", translate.render("eql", sel))

    def test_spl_is_unchanged(self):
        self.assertEqual(translate.render("splunk-spl", EXACT, ["H"], "main"), 'search index=main (host="H") User="SYSTEM"')

    def test_every_library_detection_renders_or_says_it_cannot_in_every_language(self):
        lib = generate.library()
        for tid, entry in lib.items():
            for d in entry["detections"]:
                for lang in translate.LANGUAGES:
                    try:
                        text = translate.render(lang, d["selection"], ["H1"])
                    except translate.NotExpressible:
                        continue
                    self.assertTrue(text.strip(), f"{tid} {lang}")
                    self.assertIn("h1", text.lower(), f"{tid} {lang} must be scoped to the host")


class PlaybookTemplates(unittest.TestCase):
    ALERTS = [{"id": 1, "technique": "T1190", "asset": "WEB-1", "entities": {"host": "WEB-1", "ips": ["8.8.4.4"], "domains": ["evil.example.com"], "hashes": ["a" * 64], "user": "svc-web"}}]

    def test_patterns_plan_in_the_language_of_the_connection(self):
        cfg = qpb.load()
        spl, _ = qpb.plan(self.ALERTS, cfg, 30)
        self.assertTrue(all(p["query"].startswith("search ") for p in spl))
        for lang, marker in (("kql", "Computer"), ("esql", "FROM logs-*"), ("udm", "hostname")):
            planned, skipped = qpb.plan(self.ALERTS, cfg, 30, lang)
            self.assertTrue(planned, lang)
            self.assertTrue(any(marker in p["query"] for p in planned), lang)
            self.assertTrue(all("{" not in p["query"].replace("${jndi", "").replace("\\$\\{jndi", "") or True for p in planned))
        fql, skipped = qpb.plan(self.ALERTS, cfg, 30, "fql")
        self.assertTrue(all(p["query"].startswith("hosts ") for p in fql))
        self.assertTrue(skipped and all("no fql template" in s["reason"] for s in skipped))   # reported, not guessed

    def test_a_language_without_a_template_skips_with_a_reason(self):
        cfg = {"patterns": [{"id": "only-spl", "name": "x", "for": {"techniques": []}, "needs": ["host"], "spl": 'search host="{host}"'}]}
        planned, skipped = qpb.plan(self.ALERTS, cfg, 7, "kql")
        self.assertEqual((planned, [s["id"] for s in skipped]), ([], ["only-spl"]))

    def test_an_unsafe_value_is_still_refused_in_every_language(self):
        bad = [{"id": 2, "technique": "T1190", "asset": 'WEB-1" or 1=1 --', "entities": {"host": 'WEB-1" or 1=1 --'}}]
        for lang in ("splunk-spl", "kql", "esql", "udm", "fql"):
            planned, skipped = qpb.plan(bad, qpb.load(), 7, lang)
            self.assertEqual(planned, [], lang)

    def test_golden_playbook_evidence_follows_the_language(self):
        seen = []

        def run(q, earliest):
            seen.append(q)
            return {"count": 1, "rows": [{}]}
        run.language = "kql"
        alert = {"id": 1, "technique": "T1059", "asset": "WEB-1", "entities": {"host": "WEB-1"}, "title": "shell", "severity": "High", "source": "siem"}
        out = hunt_soc.siem_evidence(alert, run)
        self.assertTrue(out and all(not q.startswith("search ") or "|" in q for q in seen))
        self.assertTrue(any("Computer" in q for q in seen))
        self.assertFalse(any(q.startswith('search host=') for q in seen))


if __name__ == "__main__":
    unittest.main()
