"""Shared fixtures for the application security tests (not a test module)."""

SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"bom-ref": "app", "name": "orders", "version": "3.4.0"}},
        "components": [
            {"bom-ref": "web", "name": "spring-boot-starter-web", "group": "org.springframework.boot", "version": "2.5.4", "purl": "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.5.4"},
            {"bom-ref": "log", "name": "spring-boot-starter-logging", "group": "org.springframework.boot", "version": "2.5.4"},
            {"bom-ref": "l4j", "name": "log4j-core", "group": "org.apache.logging.log4j", "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
            {"bom-ref": "jack", "name": "jackson-databind", "group": "com.fasterxml.jackson.core", "version": "2.12.4"},
            {"bom-ref": "junit", "name": "junit-jupiter", "version": "5.7.0", "scope": "optional"},
            {"bom-ref": "lone", "name": "commons-lang3", "version": "3.12.0"}],
        "dependencies": [{"ref": "app", "dependsOn": ["web", "jack", "junit"]}, {"ref": "web", "dependsOn": ["log"]}, {"ref": "log", "dependsOn": ["l4j"]}]}


def dep_finding(i, pkg, version, fixed, cve, sev="High", cvss=8.0, app="orders", kev=False, epss=0.1, **kw):
    f = {"id": f"FIND-{i}", "title": f"{cve} in {pkg}", "severity": sev, "cvss": cvss, "cve": cve, "scan_type": "sca", "asset": {"name": app, "type": "application"},
         "dependency": {"package": pkg, "ecosystem": "maven", "version": version, "fixed_version": fixed}, "epss": {"score": epss}, "kev": {"listed": kev}, "first_seen": "2026-09-01"}
    f.update(kw)
    return f


def code_finding(i, path, sev="High", app="orders", **kw):
    return {"id": f"FIND-{i}", "title": "SQL injection", "severity": sev, "scan_type": "sast", "asset": {"name": app, "type": "application"}, "location": {"file": path, "line": 4}, **kw}
