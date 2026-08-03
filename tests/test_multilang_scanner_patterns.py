"""
Tests for the polyglot fixture set (vulnerable-demo-multilang/) and the per-language
detection guidance added to .claude/agents/vuln-scanner.md.

These are static text-inspection tests only: they assert that each new fixture file
contains the specific vulnerable code pattern it claims to plant (per its own top-of-file
"Planted vulnerabilities" comment block, matching the numbering/CWE convention used by
vulnerable-demo-app/app.py), and that vuln-scanner.md's guidance documents a matching
technique keyword for that language. Together these prove the fixtures and the
documentation are internally consistent with each other.

This environment has no Java, Go, PHP, or Node/npm runtime available (see
vulnhunter-project's environment notes) - so nothing here compiles, executes, or lints
the sample vulnerable code, and nothing here claims the vuln-scanner subagent was
actually invoked against these fixtures. Doing that requires a live Claude Code session
running the /vulnhunt pipeline - the same caveat documented in tests/test_connectors.py
for the Tenable/Armis connectors being built against vendor docs rather than verified
against a live tenant.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

FIXTURE_DIR = REPO_ROOT / "vulnerable-demo-multilang"
SCANNER_AGENT_PATH = REPO_ROOT / ".claude" / "agents" / "vuln-scanner.md"


def read(path):
    return path.read_text(encoding="utf-8")


class JavaFixture(unittest.TestCase):
    PATH = FIXTURE_DIR / "VulnService.java"

    def test_exists_with_vulnerable_banner_and_three_numbered_vulns(self):
        text = read(self.PATH)
        self.assertIn("deliberately vulnerable", text)
        self.assertIn("DO NOT deploy", text)
        self.assertIn("1. SQL Injection via Statement", text)
        self.assertIn("2. Insecure deserialization", text)
        self.assertIn("3. Hardcoded credential", text)

    def test_plants_sql_injection_via_statement_not_preparedstatement(self):
        text = read(self.PATH)
        self.assertIn("Statement stmt = conn.createStatement();", text)
        self.assertIn('"SELECT id, email FROM users WHERE username = \'" + username', text)
        # The vulnerable query construction itself never uses a PreparedStatement -
        # the only mention of that class is in the explanatory doc-comment describing
        # what *should* have been used instead.
        self.assertNotIn("new PreparedStatement", text)
        self.assertNotIn("PreparedStatement stmt", text)
        self.assertIn("CWE-89", text)

    def test_plants_insecure_deserialization(self):
        text = read(self.PATH)
        self.assertIn("ObjectInputStream(rawIn)", text)
        self.assertIn("ois.readObject()", text)
        self.assertIn("CWE-502", text)

    def test_plants_hardcoded_credential(self):
        text = read(self.PATH)
        self.assertIn('DB_PASSWORD = "SuperSecretP@ss123"', text)
        self.assertIn("CWE-798", text)


class JavaScriptFixture(unittest.TestCase):
    PATH = FIXTURE_DIR / "vuln-app.js"

    def test_exists_with_vulnerable_banner_and_three_numbered_vulns(self):
        text = read(self.PATH)
        self.assertIn("deliberately vulnerable", text)
        self.assertIn("DO NOT deploy", text)
        self.assertIn("1. Command injection via child_process.exec", text)
        self.assertIn("2. Reflected XSS via unsanitized template string", text)
        self.assertIn("3. Hardcoded API key", text)

    def test_plants_command_injection_via_exec(self):
        text = read(self.PATH)
        self.assertIn('exec(`ping -c 1 ${host}`', text)
        self.assertIn("CWE-78", text)

    def test_plants_reflected_xss_via_template_string(self):
        text = read(self.PATH)
        self.assertIn("<h1>Welcome back, ${name}!</h1>", text)
        self.assertIn("CWE-79", text)

    def test_plants_hardcoded_api_key(self):
        text = read(self.PATH)
        self.assertIn('STRIPE_API_KEY = "sk_live_DEMO_FAKE_NOT_A_REAL_KEY', text)
        self.assertIn("CWE-798", text)


class GoFixture(unittest.TestCase):
    PATH = FIXTURE_DIR / "vulnapp.go"

    def test_exists_with_vulnerable_banner_and_three_numbered_vulns(self):
        text = read(self.PATH)
        self.assertIn("deliberately vulnerable", text)
        self.assertIn("DO NOT deploy", text)
        self.assertIn("1. Command injection via exec.Command", text)
        self.assertIn("2. SQL Injection via string-concatenated query", text)
        self.assertIn("3. World-writable file permissions (0777)", text)

    def test_plants_command_injection_via_exec_command(self):
        text = read(self.PATH)
        self.assertIn('exec.Command("sh", "-c", "ping -c 1 "+host)', text)
        self.assertIn("CWE-78", text)

    def test_plants_sql_injection_via_string_concat(self):
        text = read(self.PATH)
        self.assertIn('fmt.Sprintf("SELECT id, username, email FROM users WHERE id = %s", userID)', text)
        self.assertIn("CWE-89", text)

    def test_plants_world_writable_file_permissions(self):
        text = read(self.PATH)
        self.assertIn('os.WriteFile("/tmp/vulnapp-export.csv", data, 0777)', text)
        self.assertIn("CWE-276", text)


class PhpFixture(unittest.TestCase):
    PATH = FIXTURE_DIR / "vuln-app.php"

    def test_exists_with_vulnerable_banner_and_three_numbered_vulns(self):
        text = read(self.PATH)
        self.assertIn("deliberately vulnerable", text)
        self.assertIn("DO NOT deploy", text)
        self.assertIn("1. SQL Injection via mysqli_query string concat", text)
        self.assertIn("2. Local File Inclusion via include($_GET[...])", text)
        self.assertIn("3. unserialize() on untrusted input", text)

    def test_plants_sql_injection_via_mysqli_query_concat(self):
        text = read(self.PATH)
        self.assertIn('"SELECT id, username, email FROM users WHERE id = " . $user_id', text)
        self.assertIn("mysqli_query($conn, $query)", text)
        self.assertIn("CWE-89", text)

    def test_plants_lfi_via_include_of_get_param(self):
        text = read(self.PATH)
        self.assertIn("$page = $_GET['page'];", text)
        self.assertIn("include($page . '.php');", text)
        self.assertIn("CWE-98", text)

    def test_plants_unserialize_on_untrusted_input(self):
        text = read(self.PATH)
        self.assertIn("unserialize($raw)", text)
        self.assertIn("$_COOKIE['session_data']", text)
        self.assertIn("CWE-502", text)


class PerlFixture(unittest.TestCase):
    PATH = FIXTURE_DIR / "vuln-app.pl"

    def test_exists_with_vulnerable_banner_and_three_numbered_vulns(self):
        text = read(self.PATH)
        self.assertIn("deliberately vulnerable", text)
        self.assertIn("DO NOT deploy", text)
        self.assertIn("1. Command injection via backticks with interpolated var", text)
        self.assertIn("2. eval() on untrusted input", text)
        self.assertIn("3. Hardcoded credential", text)

    def test_plants_command_injection_via_backticks(self):
        text = read(self.PATH)
        self.assertIn("my $output = `ping -c 1 $host`;", text)
        self.assertIn("CWE-78", text)

    def test_plants_eval_on_untrusted_input(self):
        text = read(self.PATH)
        self.assertIn('my $result = eval "$expr";', text)
        self.assertIn("CWE-95", text)

    def test_plants_hardcoded_credential(self):
        text = read(self.PATH)
        self.assertIn('$DB_PASSWORD = "SuperSecretP@ss123";', text)
        self.assertIn("CWE-798", text)


class ScannerDocumentationCoversEachLanguage(unittest.TestCase):
    """Cross-checks that vuln-scanner.md documents each new target language by name
    and mentions at least one technique keyword matching what the fixtures plant -
    proving the docs and the fixtures were written consistently with each other."""

    def setUp(self):
        self.text = read(SCANNER_AGENT_PATH)

    def test_mentions_javascript_and_a_specific_technique(self):
        self.assertIn("JavaScript", self.text)
        self.assertIn("child_process.exec", self.text)

    def test_mentions_java_and_a_specific_technique(self):
        self.assertIn("Java", self.text)
        self.assertIn("PreparedStatement", self.text)

    def test_mentions_go_and_a_specific_technique(self):
        self.assertIn("Go", self.text)
        self.assertIn("html/template", self.text)

    def test_mentions_php_and_unserialize(self):
        self.assertIn("PHP", self.text)
        self.assertIn("unserialize", self.text)

    def test_mentions_perl_and_storable_thaw(self):
        self.assertIn("Perl", self.text)
        self.assertIn("Storable::thaw", self.text)

    def test_process_section_mentions_checking_file_extensions(self):
        self.assertIn("extension", self.text.lower())

    def test_generic_python_docker_and_dependency_sections_still_present(self):
        # Guardrail: the rewrite must add per-language sections without deleting the
        # pre-existing generic/Python/Docker/dependency-risk guidance.
        self.assertIn("### Generic (all languages)", self.text)
        self.assertIn("### Python", self.text)
        self.assertIn("Container/Docker issues", self.text)
        self.assertIn("Dependency risk", self.text)

    def test_process_and_output_format_sections_still_present_in_order(self):
        self.assertIn("## Process", self.text)
        self.assertIn("## Output format", self.text)
        self.assertLess(self.text.index("## Process"), self.text.index("## Output format"))


class FixtureDirectoryIsSeparateFromDemoApp(unittest.TestCase):
    def test_multilang_dir_exists_alongside_not_inside_demo_app(self):
        self.assertTrue(FIXTURE_DIR.is_dir())
        demo_app_dir = REPO_ROOT / "vulnerable-demo-app"
        self.assertTrue(demo_app_dir.is_dir())
        self.assertNotEqual(FIXTURE_DIR, demo_app_dir)

    def test_demo_app_py_untouched_planted_vulns_header_intact(self):
        # Sanity guardrail only - this suite must never alter vulnerable-demo-app/app.py
        # or its asserted finding count, which other tests depend on.
        app_py = REPO_ROOT / "vulnerable-demo-app" / "app.py"
        text = read(app_py)
        self.assertIn("Planted vulnerabilities (for scoring / demo reference):", text)

    def test_all_five_language_fixtures_present(self):
        expected = {
            "VulnService.java",
            "vuln-app.js",
            "vulnapp.go",
            "vuln-app.php",
            "vuln-app.pl",
        }
        actual = {p.name for p in FIXTURE_DIR.iterdir() if p.is_file()}
        self.assertTrue(expected.issubset(actual))


if __name__ == "__main__":
    unittest.main()
