"""
Tests for dashboard/auth/ - password hashing, signed-cookie sessions, the local user
store, and the OIDC client. User-store tests use a temporary file (never the real,
shipped users.json). The OIDC client is tested entirely against mocked HTTP (no network,
no real identity provider) - same pattern as the Tenable/Armis/ServiceNow/Jira/Splunk/
CrowdStrike connector tests.
"""
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
sys.path.insert(0, str(REPO_ROOT))

from auth import oidc, passwords, sessions, users  # noqa: E402


class PasswordHashing(unittest.TestCase):
    def test_correct_password_verifies(self):
        stored = passwords.hash_password("correct horse battery staple")
        self.assertTrue(passwords.verify_password("correct horse battery staple", stored))

    def test_wrong_password_does_not_verify(self):
        stored = passwords.hash_password("correct horse battery staple")
        self.assertFalse(passwords.verify_password("wrong password", stored))

    def test_same_password_hashes_differently_each_time(self):
        """Different random salts per call - two hashes of the same password must not
        be byte-identical, or a stored-hash leak would reveal shared passwords."""
        first = passwords.hash_password("same password")
        second = passwords.hash_password("same password")
        self.assertNotEqual(first, second)

    def test_stored_hash_carries_its_own_iteration_count(self):
        stored = passwords.hash_password("x", iterations=1000)
        self.assertIn("$1000$", stored)
        self.assertTrue(passwords.verify_password("x", stored))

    def test_malformed_stored_hash_fails_closed_not_raises(self):
        self.assertFalse(passwords.verify_password("anything", "not-a-real-hash"))
        self.assertFalse(passwords.verify_password("anything", ""))
        self.assertFalse(passwords.verify_password("anything", None))


class SessionCookies(unittest.TestCase):
    SECRET = "test-secret-do-not-use-in-real-deployment"

    def test_valid_cookie_round_trips_the_claims(self):
        cookie = sessions.create_session_cookie({"email": "a@example.com", "role": "admin"}, self.SECRET)
        claims = sessions.verify_session_cookie(cookie, self.SECRET)
        self.assertEqual(claims["email"], "a@example.com")
        self.assertEqual(claims["role"], "admin")

    def test_tampered_payload_is_rejected(self):
        cookie = sessions.create_session_cookie({"role": "user"}, self.SECRET)
        payload_b64, _, signature_b64 = cookie.partition(".")
        tampered = f"{payload_b64}x.{signature_b64}"  # corrupt the payload, keep the signature
        self.assertIsNone(sessions.verify_session_cookie(tampered, self.SECRET))

    def test_wrong_secret_is_rejected(self):
        cookie = sessions.create_session_cookie({"role": "user"}, self.SECRET)
        self.assertIsNone(sessions.verify_session_cookie(cookie, "a-different-secret"))

    def test_expired_cookie_is_rejected(self):
        cookie = sessions.create_session_cookie({"role": "user"}, self.SECRET, max_age_seconds=-1)
        self.assertIsNone(sessions.verify_session_cookie(cookie, self.SECRET))

    def test_garbage_cookie_value_does_not_raise(self):
        self.assertIsNone(sessions.verify_session_cookie("not-a-real-cookie", self.SECRET))
        self.assertIsNone(sessions.verify_session_cookie("", self.SECRET))
        self.assertIsNone(sessions.verify_session_cookie(None, self.SECRET))

    def test_cookie_carries_a_real_expiry_close_to_max_age(self):
        before = time.time()
        cookie = sessions.create_session_cookie({}, self.SECRET, max_age_seconds=3600)
        claims = sessions.verify_session_cookie(cookie, self.SECRET)
        self.assertAlmostEqual(claims["exp"], before + 3600, delta=5)


class UserStore(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tmpdir.name) / "users.json"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_load_from_missing_file_returns_empty_dict(self):
        self.assertEqual(users.load_users(self.path), {})

    def test_create_then_verify_login_succeeds(self):
        users.create_user("Someone@Example.com", "correcthorsebatterystaple", "Someone", role="admin", path=self.path)
        result = users.verify_login("someone@example.com", "correcthorsebatterystaple", path=self.path)
        self.assertIsNotNone(result)
        self.assertEqual(result["role"], "admin")
        self.assertEqual(result["email"], "someone@example.com")
        self.assertNotIn("password_hash", result)

    def test_login_is_case_insensitive_on_email(self):
        """Emails are stored lowercased - "Someone@Example.com" and
        "someone@example.com" must be the same account, not two."""
        users.create_user("someone@example.com", "correcthorsebatterystaple", "Someone", path=self.path)
        result = users.verify_login("SOMEONE@EXAMPLE.COM", "correcthorsebatterystaple", path=self.path)
        self.assertIsNotNone(result)

    def test_wrong_password_returns_none(self):
        users.create_user("someone@example.com", "correcthorsebatterystaple", "Someone", path=self.path)
        self.assertIsNone(users.verify_login("someone@example.com", "wrong password", path=self.path))

    def test_unknown_email_returns_none_not_an_error(self):
        self.assertIsNone(users.verify_login("nobody@example.com", "anything", path=self.path))

    def test_unknown_email_still_runs_the_real_password_hash_comparison(self):
        """Regression test for a timing-based email-enumeration side-channel: an
        earlier version of verify_login() used `not user or not verify_password(...)`,
        whose `or` short-circuits and skips the deliberately-slow (600k-iteration
        PBKDF2) verify_password() call entirely when the email doesn't exist - making
        an unknown-email login return near-instantly versus a known-email
        wrong-password login taking the full PBKDF2 cost, a measurable timing
        difference an attacker could use to enumerate valid emails even though both
        cases return the same `None`. verify_password() must be invoked either way."""
        with patch.object(passwords, "verify_password", wraps=passwords.verify_password) as spy:
            users.verify_login("nobody@example.com", "anything", path=self.path)
        spy.assert_called_once()

    def test_known_email_wrong_password_and_unknown_email_hit_the_same_code_path(self):
        """Both cases call verify_password() against a real-shaped hash (the actual
        user's for a known email, the module-level dummy for an unknown one) - neither
        short-circuits before reaching it."""
        users.create_user("someone@example.com", "correcthorsebatterystaple", "Someone", path=self.path)
        with patch.object(passwords, "verify_password", wraps=passwords.verify_password) as spy:
            users.verify_login("someone@example.com", "wrong password", path=self.path)
            users.verify_login("nobody@example.com", "wrong password", path=self.path)
        self.assertEqual(spy.call_count, 2)

    def test_create_user_rejects_a_short_password(self):
        with self.assertRaises(ValueError):
            users.create_user("someone@example.com", "short", "Someone", path=self.path)

    def test_create_user_rejects_a_duplicate_email(self):
        users.create_user("someone@example.com", "correcthorsebatterystaple", "Someone", path=self.path)
        with self.assertRaises(ValueError):
            users.create_user("someone@example.com", "anotherpassword1", "Someone Else", path=self.path)

    def test_create_user_rejects_an_invalid_role(self):
        with self.assertRaises(ValueError):
            users.create_user("someone@example.com", "correcthorsebatterystaple", "Someone", role="superuser", path=self.path)

    def test_set_password_then_old_password_no_longer_works(self):
        users.create_user("someone@example.com", "originalpassword1", "Someone", path=self.path)
        users.set_password("someone@example.com", "newpassword12345", path=self.path)
        self.assertIsNone(users.verify_login("someone@example.com", "originalpassword1", path=self.path))
        self.assertIsNotNone(users.verify_login("someone@example.com", "newpassword12345", path=self.path))

    def test_set_password_on_unknown_user_raises_keyerror(self):
        with self.assertRaises(KeyError):
            users.set_password("nobody@example.com", "newpassword12345", path=self.path)

    def test_create_user_accepts_a_real_team(self):
        users.create_user("someone@example.com", "correcthorsebatterystaple", "Someone", team="Platform", path=self.path)
        result = users.verify_login("someone@example.com", "correcthorsebatterystaple", path=self.path)
        self.assertEqual(result["team"], "Platform")

    def test_create_user_with_no_team_reports_none_not_a_missing_key(self):
        users.create_user("someone@example.com", "correcthorsebatterystaple", "Someone", path=self.path)
        result = users.verify_login("someone@example.com", "correcthorsebatterystaple", path=self.path)
        self.assertIsNone(result["team"])

    def test_set_team_persists_and_is_reflected_on_login(self):
        users.create_user("someone@example.com", "correcthorsebatterystaple", "Someone", path=self.path)
        users.set_team("someone@example.com", "Identity", path=self.path)
        result = users.verify_login("someone@example.com", "correcthorsebatterystaple", path=self.path)
        self.assertEqual(result["team"], "Identity")

    def test_set_team_blank_clears_a_previous_team(self):
        users.create_user("someone@example.com", "correcthorsebatterystaple", "Someone", team="Platform", path=self.path)
        users.set_team("someone@example.com", "", path=self.path)
        result = users.verify_login("someone@example.com", "correcthorsebatterystaple", path=self.path)
        self.assertIsNone(result["team"])

    def test_set_team_on_unknown_user_raises_keyerror(self):
        with self.assertRaises(KeyError):
            users.set_team("nobody@example.com", "Platform", path=self.path)

    def test_set_role_persists_and_is_reflected_on_login(self):
        users.create_user("someone@example.com", "correcthorsebatterystaple", "Someone", role="user", path=self.path)
        users.set_role("someone@example.com", "admin", path=self.path)
        result = users.verify_login("someone@example.com", "correcthorsebatterystaple", path=self.path)
        self.assertEqual(result["role"], "admin")

    def test_set_role_rejects_an_invalid_role(self):
        users.create_user("someone@example.com", "correcthorsebatterystaple", "Someone", path=self.path)
        with self.assertRaises(ValueError):
            users.set_role("someone@example.com", "superuser", path=self.path)

    def test_set_role_on_unknown_user_raises_keyerror(self):
        with self.assertRaises(KeyError):
            users.set_role("nobody@example.com", "admin", path=self.path)

    def test_list_users_never_includes_the_password_hash(self):
        users.create_user("someone@example.com", "correcthorsebatterystaple", "Someone", role="admin", team="Platform", path=self.path)
        listed = users.list_users(path=self.path)
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0], {"email": "someone@example.com", "name": "Someone", "role": "admin", "team": "Platform"})

    def test_list_users_is_sorted_by_email(self):
        users.create_user("zeta@example.com", "correcthorsebatterystaple", "Zeta", path=self.path)
        users.create_user("alpha@example.com", "correcthorsebatterystaple", "Alpha", path=self.path)
        listed = users.list_users(path=self.path)
        self.assertEqual([u["email"] for u in listed], ["alpha@example.com", "zeta@example.com"])

    def test_list_users_from_missing_file_returns_empty_list(self):
        self.assertEqual(users.list_users(self.path), [])


class RealSeedFileIsValid(unittest.TestCase):
    def test_shipped_users_file_is_well_formed_and_has_both_demo_roles(self):
        all_users = users.load_users()
        self.assertIsInstance(all_users, dict)
        roles = {info["role"] for info in all_users.values()}
        self.assertIn("admin", roles)
        self.assertIn("user", roles)
        for email, info in all_users.items():
            self.assertEqual(email, email.lower())
            self.assertTrue(info["password_hash"].startswith("pbkdf2_sha256$"))


class OidcConfiguration(unittest.TestCase):
    ENV_VARS = ("OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_REDIRECT_URI")

    def setUp(self):
        self.patcher = patch.dict("os.environ", {}, clear=False)
        self.patcher.start()
        for var in self.ENV_VARS:
            __import__("os").environ.pop(var, None)

    def tearDown(self):
        self.patcher.stop()

    def test_not_configured_without_any_env_vars(self):
        self.assertFalse(oidc.is_configured())

    def test_not_configured_with_only_some_env_vars(self):
        import os
        os.environ["OIDC_ISSUER"] = "https://idp.example.com"
        os.environ["OIDC_CLIENT_ID"] = "client-123"
        self.assertFalse(oidc.is_configured())

    def test_configured_once_all_four_env_vars_are_set(self):
        import os
        os.environ.update({
            "OIDC_ISSUER": "https://idp.example.com",
            "OIDC_CLIENT_ID": "client-123",
            "OIDC_CLIENT_SECRET": "secret-abc",
            "OIDC_REDIRECT_URI": "https://dashboard.example.com/api/auth/oidc/callback",
        })
        self.assertTrue(oidc.is_configured())


class OidcFlow(unittest.TestCase):
    """The full Authorization Code + PKCE flow, against a mocked requests.Session
    shaped like a real OIDC discovery document - never a real network call, same rule
    as every other connector's tests in this repo."""

    DISCOVERY_DOC = {
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "userinfo_endpoint": "https://idp.example.com/userinfo",
    }

    def setUp(self):
        env_patch = patch.dict("os.environ", {
            "OIDC_ISSUER": "https://idp.example.com",
            "OIDC_CLIENT_ID": "client-123",
            "OIDC_CLIENT_SECRET": "secret-abc",
            "OIDC_REDIRECT_URI": "https://dashboard.example.com/api/auth/oidc/callback",
        })
        env_patch.start()
        self.addCleanup(env_patch.stop)

    def test_generate_pkce_pair_produces_a_valid_s256_challenge(self):
        import base64
        import hashlib
        verifier, challenge = oidc.generate_pkce_pair()
        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        self.assertEqual(challenge, expected)

    def test_build_authorize_url_includes_pkce_and_state(self):
        url = oidc.build_authorize_url("state-xyz", "challenge-abc", discovery_doc=self.DISCOVERY_DOC)
        self.assertTrue(url.startswith("https://idp.example.com/authorize?"))
        self.assertIn("state=state-xyz", url)
        self.assertIn("code_challenge=challenge-abc", url)
        self.assertIn("code_challenge_method=S256", url)
        self.assertIn("client_id=client-123", url)

    def test_exchange_code_for_token_posts_the_right_grant(self):
        mock_session = MagicMock()
        mock_session.post.return_value.json.return_value = {"access_token": "at-123", "id_token": "it-123"}
        result = oidc.exchange_code_for_token("auth-code", "verifier-xyz", discovery_doc=self.DISCOVERY_DOC, session=mock_session)
        self.assertEqual(result["access_token"], "at-123")
        _, kwargs = mock_session.post.call_args
        self.assertEqual(kwargs["data"]["grant_type"], "authorization_code")
        self.assertEqual(kwargs["data"]["code"], "auth-code")
        self.assertEqual(kwargs["data"]["code_verifier"], "verifier-xyz")
        self.assertEqual(kwargs["data"]["client_secret"], "secret-abc")

    def test_fetch_userinfo_sends_a_bearer_token(self):
        mock_session = MagicMock()
        mock_session.get.return_value.json.return_value = {"email": "person@example.com", "name": "Person"}
        result = oidc.fetch_userinfo("at-123", discovery_doc=self.DISCOVERY_DOC, session=mock_session)
        self.assertEqual(result["email"], "person@example.com")
        _, kwargs = mock_session.get.call_args
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer at-123")

    def test_discover_fetches_the_real_well_known_path(self):
        mock_session = MagicMock()
        mock_session.get.return_value.json.return_value = self.DISCOVERY_DOC
        oidc.discover("https://idp.example.com", session=mock_session)
        mock_session.get.assert_called_once_with("https://idp.example.com/.well-known/openid-configuration")


if __name__ == "__main__":
    unittest.main()
