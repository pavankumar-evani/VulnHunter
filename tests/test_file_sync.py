"""
Tests for running replicas without a shared volume: the file-to-database sync that keeps each
replica's findings and policy files in step (two "pods" = two directories and one database), and
live reload of secrets that a key vault mount rotates.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine  # noqa: E402

from remediation.ingest import merge  # noqa: E402
from remediation.utils import file_sync, secret_files  # noqa: E402

FINDINGS = "remediation/output/normalized-findings.json"
CONFIG = "remediation/config/priority_weights.yaml"
PLAYBOOK = "remediation/output/FIND-1-fix.yml"


def f(n, **kw):
    d = {"id": f"FIND-{n}", "source": "tenable", "title": f"Issue {n}", "severity": "High", "cve": None,
         "asset": {"name": f"host{n}", "type": "unix-server"}, "kev": None, "epss": None, "last_seen": "2026-10-01"}
    d.update(kw)
    return d


class Pods(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'db.sqlite'}", connect_args={"timeout": 30})
        self.image = Path(self.tmp.name) / "image"
        self.write(self.image, CONFIG, "weights: {kev: 5}\n")
        self.write(self.image, FINDINGS, json.dumps([f(1)]))
        self.write(self.image, PLAYBOOK, "- hosts: x\n")

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    @staticmethod
    def write(root, rel, text):
        p = Path(root) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def pod(self, name):
        """A replica: a copy of the image's files plus its own FileSync."""
        root = Path(self.tmp.name) / name
        for rel in (CONFIG, FINDINGS, PLAYBOOK):
            self.write(root, rel, (self.image / rel).read_text(encoding="utf-8"))
        return file_sync.FileSync(root, engine=self.engine, interval=0)

    def read(self, pod, rel):
        p = pod.root / rel
        return p.read_text(encoding="utf-8") if p.exists() else None


class SyncTests(Pods):
    def test_the_first_replica_seeds_the_database_and_the_second_pulls_it(self):
        a, b = self.pod("a"), self.pod("b")
        self.assertEqual(a.sync()["pushed"], 3)  # config, findings, playbook seeded from the image
        self.assertEqual(b.sync()["pushed"], 0)
        self.assertEqual(self.read(b, CONFIG), "weights: {kev: 5}\n")

    def test_a_change_on_one_replica_reaches_the_other(self):
        a, b = self.pod("a"), self.pod("b")
        a.sync()
        b.sync()
        self.write(a.root, FINDINGS, json.dumps([f(1), f(2)]))
        self.assertEqual(a.sync()["pushed"], 1)
        self.assertEqual(b.sync()["pulled"], 1)
        self.assertEqual(len(json.loads(self.read(b, FINDINGS))), 2)
        self.assertEqual(b.sync()["pulled"], 0)  # nothing more to do

    def test_a_new_file_and_a_deletion_propagate(self):
        a, b = self.pod("a"), self.pod("b")
        a.sync()
        b.sync()
        self.write(a.root, "remediation/output/FIND-2-new.yml", "- hosts: y\n")
        (a.root / PLAYBOOK).unlink()
        a.sync()
        b.sync()
        self.assertEqual(self.read(b, "remediation/output/FIND-2-new.yml"), "- hosts: y\n")
        self.assertIsNone(self.read(b, PLAYBOOK))

    def test_a_late_replica_does_not_resurrect_stale_image_defaults(self):
        a = self.pod("a")
        a.sync()
        (a.root / PLAYBOOK).unlink()  # the cluster removed the sample playbook
        a.sync()
        late = self.pod("late")  # starts from the image, which still has it
        late.sync()
        self.assertIsNone(self.read(late, PLAYBOOK))
        self.assertEqual(self.read(late, CONFIG), "weights: {kev: 5}\n")  # a kept default stays

    def test_both_changed_means_the_database_wins_and_is_counted(self):
        a, b = self.pod("a"), self.pod("b")
        a.sync()
        b.sync()
        self.write(a.root, CONFIG, "weights: {kev: 9}\n")
        a.sync()
        self.write(b.root, CONFIG, "weights: {kev: 1}\n")
        stats = b.sync()
        self.assertEqual(stats["conflicts"], 1)
        self.assertEqual(self.read(b, CONFIG), "weights: {kev: 9}\n")

    def test_throttle_and_force(self):
        a = file_sync.FileSync(self.pod("a").root, engine=self.engine, interval=60)
        self.assertIsNotNone(a.sync(now=1000))
        self.assertIsNone(a.sync(now=1010))
        self.assertIsNotNone(a.sync(force=True, now=1011))

    def test_off_by_default(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("QUANTA_FILES_BACKEND", None)
            self.assertFalse(file_sync.enabled())
            self.assertIsNone(file_sync.sync_if_enabled(force=True))


class MergeAcrossReplicas(Pods):
    def test_two_replicas_merging_in_turn_lose_nothing_and_keep_ids_unique(self):
        a, b = self.pod("a"), self.pod("b")
        a.sync()
        b.sync()
        # a replica merges against its own copy, syncing first and publishing after, as merge() does
        for pod, source, title in ((a, "tenable", "from A"), (b, "qualys", "from B"), (a, "tenable", "from A again")):
            pod.sync(force=True)
            path = pod.root / FINDINGS
            merge.merge([{"title": title, "severity": "High", "asset": {"name": "h"}, "cve": None, "source_ref": title}], source, path=path)
            pod.sync(force=True)
        a.sync(force=True)
        b.sync(force=True)
        for pod in (a, b):
            ids = [x["id"] for x in json.loads(self.read(pod, FINDINGS))]
            self.assertEqual(len(ids), len(set(ids)))
            self.assertEqual(len(ids), 4)  # the seeded one + three new


class SecretReloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "key"
        self.path.write_text("old-token\n", encoding="utf-8")
        secret_files._loaded.clear()
        self.env = patch.dict(os.environ, {"QUANTA_METRICS_TOKEN_FILE": str(self.path)})
        self.env.start()
        os.environ.pop("QUANTA_METRICS_TOKEN", None)
        secret_files.load_file_env()

    def tearDown(self):
        self.env.stop()
        secret_files._loaded.clear()
        self.tmp.cleanup()

    def rotate(self, text):
        self.path.write_text(text, encoding="utf-8")
        st = self.path.stat()
        os.utime(self.path, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))

    def test_a_rotated_secret_is_picked_up_without_a_restart(self):
        self.assertEqual(os.environ["QUANTA_METRICS_TOKEN"], "old-token")
        self.assertEqual(secret_files.reload_changed(), [])
        self.rotate("new-token\n")
        self.assertEqual(secret_files.reload_changed(), ["QUANTA_METRICS_TOKEN"])
        self.assertEqual(os.environ["QUANTA_METRICS_TOKEN"], "new-token")

    def test_an_empty_or_missing_file_keeps_the_old_value(self):
        self.rotate("\n")
        self.assertEqual(secret_files.reload_changed(), [])
        self.path.unlink()
        self.assertEqual(secret_files.reload_changed(), [])
        self.assertEqual(os.environ["QUANTA_METRICS_TOKEN"], "old-token")

    def test_an_explicit_override_is_left_alone(self):
        os.environ["QUANTA_METRICS_TOKEN"] = "set-by-hand"
        self.rotate("new-token\n")
        self.assertEqual(secret_files.reload_changed(), [])
        self.assertEqual(os.environ["QUANTA_METRICS_TOKEN"], "set-by-hand")


if __name__ == "__main__":
    unittest.main()
