"""
Tests for remediation/enrichment/cloud_provider.py - a disclosed keyword classifier
over each cloud-infrastructure asset's own real `os` string, not a live CSPM
integration (this app has no real AWS/Azure/GCP/OCI/Alibaba credentials).
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment.cloud_provider import classify_cloud_provider, tag_cloud_provider  # noqa: E402


def _finding(asset_type, os_str, **overrides):
    f = {"id": "FIND-TEST", "asset": {"type": asset_type, "os": os_str}}
    f.update(overrides)
    return f


class ProviderClassification(unittest.TestCase):
    def test_amazon_eks_is_aws(self):
        self.assertEqual(classify_cloud_provider(_finding("cloud-infrastructure", "Amazon EKS worker node (Amazon Linux 2)")), "AWS")

    def test_aws_managed_resource_is_aws(self):
        self.assertEqual(classify_cloud_provider(_finding("cloud-infrastructure", "AWS-managed cloud resource (AWS Lambda)")), "AWS")

    def test_azure_kubernetes_service_is_azure(self):
        self.assertEqual(classify_cloud_provider(_finding("cloud-infrastructure", "Azure Kubernetes Service node")), "Azure")

    def test_google_kubernetes_engine_is_gcp(self):
        self.assertEqual(classify_cloud_provider(_finding("cloud-infrastructure", "Google Kubernetes Engine node")), "GCP")

    def test_gcp_managed_resource_is_gcp(self):
        self.assertEqual(classify_cloud_provider(_finding("cloud-infrastructure", "GCP-managed cloud resource (Google Cloud Storage)")), "GCP")

    def test_oracle_oke_is_oci(self):
        self.assertEqual(classify_cloud_provider(_finding("cloud-infrastructure", "Oracle Container Engine for Kubernetes (OKE) node")), "OCI")

    def test_alibaba_ack_is_alibaba_cloud(self):
        self.assertEqual(classify_cloud_provider(_finding("cloud-infrastructure", "Alibaba Cloud Container Service for Kubernetes (ACK) node")), "Alibaba Cloud")

    def test_terraform_is_honestly_unattributed_not_guessed(self):
        self.assertIsNone(classify_cloud_provider(_finding("cloud-infrastructure", "Terraform-provisioned cloud resource")))

    def test_self_managed_kubernetes_is_honestly_unattributed(self):
        self.assertIsNone(classify_cloud_provider(_finding("cloud-infrastructure", "Kubernetes 1.2x (self-managed cluster node)")))

    def test_non_cloud_asset_type_is_none_even_with_provider_keyword(self):
        # A non-cloud asset whose OS string happens to mention a provider name (e.g. a
        # workstation named after a project) must not be misclassified as that
        # provider's managed infrastructure - the asset `type` gate comes first.
        self.assertIsNone(classify_cloud_provider(_finding("windows-endpoint", "Windows 11 - Azure migration test VM")))

    def test_missing_asset_is_none(self):
        self.assertIsNone(classify_cloud_provider({"id": "FIND-TEST"}))


class TagCloudProvider(unittest.TestCase):
    def test_adds_field_to_every_finding(self):
        findings = [
            _finding("cloud-infrastructure", "Amazon EKS worker node (Amazon Linux 2)"),
            _finding("windows-server", "Microsoft Windows Server 2019"),
        ]
        tagged = tag_cloud_provider(findings)
        self.assertEqual(tagged[0]["cloud_provider"], "AWS")
        self.assertIsNone(tagged[1]["cloud_provider"])

    def test_does_not_mutate_input(self):
        findings = [_finding("cloud-infrastructure", "Amazon EKS worker node (Amazon Linux 2)")]
        tag_cloud_provider(findings)
        self.assertNotIn("cloud_provider", findings[0])


if __name__ == "__main__":
    unittest.main()
