"""The sign-in page describes the product as it is today and no longer calls itself a demo build."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "dashboard" / "static" / "js"


class LoginCopyTests(unittest.TestCase):
    def test_hero_names_the_current_capabilities(self):
        hero = (ROOT / "authHero.js").read_text(encoding="utf-8")
        for phrase in ("Eight modules", "Security Posture Review", "relationship graphs", "approved by a person"):
            self.assertIn(phrase, hero)
        self.assertNotIn("closes the loop", hero)

    def test_notice_is_not_the_old_demo_text(self):
        login = (ROOT / "pages" / "login.js").read_text(encoding="utf-8")
        self.assertNotIn("local demo build", login)
        self.assertIn("simulated sample data", login)


if __name__ == "__main__":
    unittest.main()
