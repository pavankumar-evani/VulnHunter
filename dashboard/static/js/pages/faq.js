export const title = "FAQ";

const FAQS = [
  ["How are findings assigned to people and teams?",
    "Each finding can carry an assignee, a team, a work status (open, in progress, blocked, " +
    "resolved) and notes. Teams are first-class records with a manager. Auto-route fills " +
    "gaps from asset ownership (preview first). Ownership Analytics shows coverage and " +
    "workload; Assignments is the work queue; Users & Teams manages people. Resolved is the " +
    "owner's report - the next scan confirms it."],
  ["Does this actually scan production infrastructure?",
    "No. Infra findings are ingested from Tenable/Armis exports or their APIs; " +
    "Quanta itself never touches a target system. The connectors are built against " +
    "each vendor's public API docs and unit-tested against mocked HTTP - they've never " +
    "been exercised against a real Tenable/Armis tenant (no credentials were available " +
    "while building them)."],
  ["Does anything here ever auto-apply to real systems?",
    "No. Every generated Ansible playbook is a reviewable, unexecuted file. The " +
    "dashboard's Run Pipeline and AI Assist actions default to a dry-run/preview and " +
    "require an explicit confirm checkbox to spend real API usage - see the safety " +
    "model in KNOWLEDGE_TRANSFER.md §4.3."],
  ["What languages can the code scanner find vulnerabilities in?",
    "Python, JavaScript/TypeScript, Java, Go, PHP, and Perl source, per " +
    ".claude/agents/vuln-scanner.md's per-language detection guidance. The scanner " +
    "itself is a Claude Code subagent (model-driven static analysis), not a compiled " +
    "tool - it doesn't need a compiler for whatever language it's scanning."],
  ["Is this agent-based or agentless scanning?",
    "Code scanning (/quanta-scan) is agentless - it reads source code already in a git " +
    "repo, nothing is installed on any target. Infrastructure findings come from " +
    "Tenable/Armis, and whether THEY use an agent or an agentless scan is a " +
    "configuration choice made in those tools, not something Quanta re-implements."],
  ["Is this SOC2 / NIST / PCI compliant?",
    "No, and it can't claim to be from a codebase alone - those are audits/" +
    "certifications performed by a licensed third party over operational evidence, not " +
    "a coding deliverable. See docs/COMPLIANCE_MAPPING.md in the repo for an honest, " +
    "explicitly-non-certifying mapping of what exists today to common control " +
    "categories."],
  ["Does it support multiple clients/tenants (MSSP)?",
    "There's a tenant switcher in the sidebar for demo purposes - it partitions the " +
    "same real dataset by asset category to show what an MSSP view could look like. " +
    "It is NOT real per-tenant authentication or data isolation (localStorage-only, " +
    "unconnected to login); that needs a real per-tenant data boundary layered on top " +
    "of the database and auth that already exist today (see KNOWLEDGE_TRANSFER.md " +
    "§11.1). Audited directly " +
    "(2026-09-01): no server route trusts a client-supplied tenant ID today, so " +
    "there's no real gap yet - only a standard (NIST AC-3/AC-4/AC-6, OWASP BOLA) to " +
    "build any future per-team/tenant scoping against from day one (see " +
    "KNOWLEDGE_TRANSFER.md §11)."],
  ["Can I formally accept risk on a finding instead of remediating it?",
    "Yes - the Exceptions page is a real, documented risk-acceptance workflow: " +
    "request an exception with a reason/compensating control, a requester, and an " +
    "approver, with an expiry date it auto-expires against unless revoked first. One " +
    "honest scope limit: an active exception doesn't yet pause SLA-breach counting in " +
    "the priority engine."],
  ["Does it track who owns each asset?",
    "Yes - the Asset Inventory page aggregates every asset with findings against it " +
    "and lets you attach an owner/team, stored in a real, editable local file - not a " +
    "sync from a real CMDB/asset-management system. It also has a CMDB CSV import " +
    "panel to bulk-assign owner/team from an uploaded export."],
  ["Is \"Container Vulnerabilities\" the same as \"Container/Host Runtime Security\"?",
    "No - genuinely different, same build-time-vs-runtime distinction real container-" +
    "security products draw. Container Vulnerabilities (Application Vulnerabilities " +
    "hub) is static Dockerfile/base-image analysis from code scanning. Container/Host " +
    "Runtime Security (Infrastructure hub) is Falco-style behavioral detection on an " +
    "already-running container/host. Different tools, different findings in real " +
    "deployments - kept as two categories here too."],
  ["Are Container and API Vulnerabilities real categories, or placeholders?",
    "Both real, different maturity. Container Vulnerabilities surfaces findings the " +
    "scanner already detected (root user, baked-in secrets, unpinned base image) - they " +
    "were just falling into a generic \"Other\" bucket before a small category-mapping " +
    "fix. API Vulnerabilities is new detection guidance for future scans (missing auth, " +
    "wildcard CORS, mass assignment) - wired up and real, but shows 0 findings today " +
    "since the demo app has no planted example (DAST, by contrast, now has real sample " +
    "data - see the next answer)."],
  ["Where did SAST/DAST/Secrets/SCA/Container/API go from the sidebar?",
    "Still real, working pages - just not separate menu entries. They're cards on the " +
    "Application Vulnerabilities hub (/appsec) instead, so the main menu shows one " +
    "entry per domain, not per sub-category. Infrastructure Vulnerabilities got the " +
    "same treatment: /infrastructure splits it into OS/Network/Network Security/OT-IoT/" +
    "Cloud cards. Cloud Infrastructure and DAST both used to honestly show 0 findings; " +
    "both now have real sample data (~300 each, real CVEs from NVD for Cloud, real " +
    "CWE/OWASP classes for DAST since dynamic-testing bugs aren't CVE-numbered). API " +
    "Vulnerabilities still shows 0, same honest treatment, for the reason above."],
  ["Is the AI Vulnerabilities page's MITRE ATLAS mapping authoritative?",
    "No, and it says so on the page itself. The twelve AI/ML vulnerability categories " +
    "(prompt injection, model poisoning, supply-chain compromise, etc.) each cross-" +
    "reference a MITRE ATLAS tactic/technique - this module's own reading of published " +
    "ATLAS docs, not a verified mapping, same \"suggestion to verify\" posture as the " +
    "existing ATT&CK heat map. Unlike API Vulnerabilities, this one isn't stuck at 0: " +
    "vulnerable-demo-app/ai_assistant.py plants 4 real AI/ML vulnerabilities (hardcoded " +
    "LLM API key, insecure model deserialization, prompt injection, excessive agency), " +
    "a real scan found all 4, and 3 tag against this taxonomy for real - Prompt " +
    "Injection, AI Supply Chain Compromise, and Excessive Agency show genuine non-zero " +
    "counts. Every other category is still honestly at 0 - nothing faked to look " +
    "populated."],
  ["Is the owner suggestion on Asset Inventory real machine learning?",
    "No. It's three transparent, weighted pattern-matching signals - hostname naming " +
    "convention, IP subnet, and asset type (plus MAC vendor matching for type " +
    "suggestions) - against assets that already have an owner, with the exact reasoning " +
    "shown on hover. Not a trained model: this demo's asset list has about a dozen " +
    "entries, far too few to train or validate real ML on. Never auto-applied - a " +
    "one-click \"Use\" button, same posture as the ATT&CK tags and compensating-control " +
    "suggestions."],
  ["Is there real machine learning anywhere in this app now?",
    "Yes, on /ml-insights - real scikit-learn, genuinely fit at request time: " +
    "IsolationForest anomaly detection (per asset type), KMeans risk-archetype " +
    "clustering, and TF-IDF + cosine-similarity \"Similar findings\" search. All three " +
    "are unsupervised (no labeled examples needed), unlike owner suggestion above which " +
    "would need labels this demo doesn't have enough of. It never replaces or feeds into " +
    "the deterministic Remediation Policy or Priority Rules engines, and it still doesn't " +
    "do supervised learning or remediation-outcome prediction - there's no real " +
    "resolved/fixed_at field anywhere to learn that from. See the full FAQ.md entry for " +
    "the complete reasoning."],
  ["Is there a login now? What are the demo credentials?",
    "Yes - a real local login MVP, not a placeholder. Two demo accounts ship in the " +
    "seed file (intentionally public, since it's a demo seed, not a real secret): " +
    "admin@quanta.local / ChangeMe123! (admin) and analyst@quanta.local / " +
    "ChangeMe123! (user). There's also real OpenID Connect (SSO) client code, but it " +
    "stays inert - the \"Sign in with SSO\" button won't even appear - unless a real " +
    "identity provider is configured. See dashboard/README.md's Authentication section " +
    "for the full design, including exactly which routes require login."],
  ["Does a suggested compensating control mean it's approved or certified?",
    "No. The Exceptions request form suggests candidate compensating controls based " +
    "on keywords in the finding's title/description - same explicitly-non-authoritative " +
    "heuristic as the MITRE ATT&CK tagging. It's a drafting aid, not a determination " +
    "that a control is actually in place, adequate, or certified by anyone."],
  ["Is the Inbox real messaging between users?",
    "No. It's a feed of system-generated notifications only - SLA breaches, KEV-listed " +
    "findings, expiring exceptions, pending generic-ingested findings - never a message " +
    "one person wrote to another. Real person-to-person messaging would need the auth/" +
    "user system this wave added plus a persistence layer to store messages against."],
  ["Is the internal/external-facing tag on the Risk dashboard from a real network scan?",
    "No. It's manually set only, exactly like asset ownership - there's no network " +
    "scan, firewall analysis, or exposure-scanning tool behind it. It defaults to " +
    "\"Unknown\" until someone sets it."],
  ["Does Notification Settings actually send real emails?",
    "Yes, if you configure real SMTP (SMTP_HOST/SMTP_PORT/SMTP_FROM_ADDRESS " +
    "environment variables) - genuinely inert until then, honestly shown as " +
    "configured/not-configured rather than implying it works either way. Uses " +
    "Python's stdlib smtplib, no new dependency; not exercised against a real mail " +
    "server during development - send yourself a real test first. Scheduled reports " +
    "and team alerts both run on an in-process timer (hourly by default) that only " +
    "ticks while the dashboard server stays running - point a real external cron at " +
    "POST /api/notification-settings/run-checks-now for delivery that doesn't depend " +
    "on server uptime."],
  ["Does the AD/PAM integration on Remediation Policy connect to a real directory or vault?",
    "AD, yes if configured (AD_SERVER/AD_BASE_DN environment variables) - but strictly " +
    "read-only, only checking group membership for a Remediation Approval, never " +
    "creating/modifying/resetting anything; honestly reported as null (\"not checked\") " +
    "when unconfigured, never faked as pass/fail. PAM is different in kind, not just " +
    "configuration: this app never holds or fetches a live privileged credential at " +
    "all - a generated playbook instead gets a real Vault/CyberArk Ansible lookup " +
    "snippet in its vars block, and the actual secret fetch happens later, when your " +
    "own change-management process runs that playbook. See REMEDIATION_WORKFLOWS.md's " +
    "\"Remediation Policy\" section for the full model."],
  ["What's the difference between an Exception and a Remediation Approval?",
    "Opposite questions. An Exception means \"accept the risk instead of fixing this\" " +
    "- a time-boxed waiver. A Remediation Approval means \"yes, proceed with fixing " +
    "this\" - the human sign-off a normal/emergency-change-type finding needs before " +
    "its generated playbook is considered ready to hand off. A finding only ever needs " +
    "one or the other, never both."],
  ["Why don't domains like IaC/SCA/Runtime have a maintenance window the way OS/Endpoint do?",
    "Because they're genuinely different remediation mechanisms. OS/Endpoint/Network " +
    "really do get a scheduled patch pushed to a running system in a time window. IaC/" +
    "SCA findings get fixed by a pull request merging (auto-mergeable for low-risk " +
    "patch-level changes, the real Renovate/Dependabot convention) - nothing is being " +
    "patched live. Runtime findings (behavioral alerts) are investigative SOC triage, " +
    "not a patchable CVE at all. The cadence/window fields still exist for consistency, " +
    "but for these three, read them as \"how often to check,\" not \"when the outage happens.\""],
  ["Is \"cloud vulnerabilities\" just Kubernetes, or real cloud-provider issues too?",
    "Both, and it's all real. The ~1,400 cloud-infrastructure sample findings are " +
    "genuine NVD-sourced CVEs spanning Kubernetes/Docker/Terraform AND real, provider-" +
    "specific services - Amazon S3/Lambda/IAM/RDS/CloudFormation, Azure Active " +
    "Directory/Storage/DevOps, Google Cloud Storage/SDK. They get the same KEV/EPSS " +
    "enrichment and priority scoring as every other category, plus a dedicated cloud " +
    "Remediation Policy domain with AWS/Azure/GCP-native PAM backends."],
  ["Where does my data go?",
    "Nowhere - everything is local files in this repo (git history, JSON, YAML). " +
    "There's no cloud service and no telemetry."],
  ["How much does a real scan or AI-assist call cost?",
    "Running /quanta-scan or /remediate for real calls the Claude API and spends usage/" +
    "credits, spend-capped via --max-budget-usd (default shown on the Run Pipeline " +
    "page). AI Assist's real (confirmed) calls do the same, at whatever your Claude " +
    "plan's per-request cost is - always preview first, it's free."],
  ["Is Quantum Readiness a real \"quantum vulnerability scanner\"?",
    "No - no such product category exists to honestly claim, since a quantum computer " +
    "capable of breaking real RSA/ECDSA doesn't exist yet. It classifies real, " +
    "already-normalized findings by a disclosed keyword heuristic (same tier as ATT&CK " +
    "tagging) into asymmetric crypto (RSA/ECDSA/Diffie-Hellman - genuinely quantum-" +
    "relevant, Shor's algorithm breaks these) and legacy protocol (SSLv2/SSLv3/3DES/" +
    "RC4/MD5-sig - classically broken already, not itself quantum-relevant). Migration " +
    "guidance cites real NIST FIPS 203/204/205 (Aug 2024) and NIST IR 8547 (draft) - " +
    "2030 deprecation/2035 disallowal for the weaker 112-bit tier, e.g. RSA-2048; CNSA " +
    "2.0 is a separate NSS-specific framework with its own dates, not the same ones. " +
    "Nothing fabricated - every matched " +
    "finding is real, already-shipped sample data."],
  ["Is there a single aggregate score on the main dashboard, like Tenable's Cyber Exposure Score?",
    "Yes, on the Overview page - real-time, not fabricated. Deliberately NOT claimed as " +
    "equivalent to Tenable's Cyber Exposure Score (proprietary, unpublished formula) or " +
    "any other named product - research confirms no citable industry-standard aggregate " +
    "exposure score exists (SSVC is a per-vulnerability decision tree, not a fleet " +
    "aggregate). It's an original, disclosed rollup of three real signals: average " +
    "per-asset Risk Score, CISA KEV prevalence, and average FIRST.org EPSS - see the " +
    "\"How is this calculated?\" panel right under the tile for the full math."],
  ["Is \"staging validated\" on Remediation Approvals a real staging-environment check?",
    "No - metadata only, same honest pattern as ad_group_validated on the same record. " +
    "It records who attests a change was tested in staging and when (ISO/IEC " +
    "27002:2022 §8.32) - no real staging environment behind it. The page also now " +
    "surfaces each finding's real generated-playbook rollback procedure (a genuine " +
    "\"# Rollback: ...\" comment the fixer subagent wrote) - \"Not yet available\" " +
    "honestly means no playbook has been generated for that finding yet."],
  ["Does this use React, Node.js, or Perl? Is there a real Infrastructure-as-Code layer?",
    "No React, no Node.js/npm - deliberately, since this machine had no Node.js/npm " +
    "installed and an untested React build isn't \"modern,\" it's just unverified. See " +
    "dashboard/README.md's \"Why FastAPI + vanilla JS\" section. Perl only appears as " +
    "one of six languages the code scanner can find vulnerabilities IN, not something " +
    "Quanta is built in. Real Infrastructure-as-Code already exists though: the " +
    "remediation-fixer subagents generate real, reviewable Ansible playbooks (or " +
    "PowerShell DSC for Windows) - never auto-applied. /api/*'s JSON contract is " +
    "already the seam a future React frontend would build against."],
  ["How do I log out, and why does it show two different messages?",
    "Logging out (account menu, Profile, or idle-timeout) signs you out first, then " +
    "sends you to a display-only confirmation screen - it shows \"signed out after " +
    "inactivity\" or a generic \"session ended\" message depending on which happened; " +
    "the page itself never calls the logout API."],
  ["How do I change my password?",
    "On the Profile page: one field, a new password (8+ characters). No \"confirm " +
    "password\" or \"current password\" field - submitting changes it immediately."],
  ["How do I add a user or change someone's role/team?",
    "Admin Settings, \"Team Management\" (admin-only). Add User takes email/name/" +
    "password/role/team. For an existing user, role is a per-row dropdown that saves " +
    "on change; team is a free-text field with its own Save button. This is also the " +
    "entire RBAC configuration surface - there's no separate RBAC settings page."],
  ["How do I change an asset's owner, team, IP/MAC, or environment?",
    "Click \"Edit\" on that asset's row in Asset Inventory. The modal covers Owner, " +
    "Team, IP, MAC, Environment, and a remediation-schedule override - each field " +
    "saves independently. Bulk changes come from the CMDB CSV import panel on the " +
    "same page. Internal/external-facing classification is set separately, inline on " +
    "the Risk Management page."],
  ["Can I change an asset's EOL/EOS status?",
    "No - and this is worth being precise about, since it looks editable from a " +
    "distance. EOL/EOS is a read-only badge, computed server-side by matching the " +
    "asset's OS string against a real vendor-lifecycle table. There is no form field " +
    "for it anywhere in the app, on purpose: it's a fact derived from the OS string, " +
    "not an opinion an owner should be able to override."],
  ["How do I request an exception - and is there a separate approval step?",
    "Request one from the Exceptions page: pick the finding, write a reason (keyword-" +
    "suggested compensating controls can be inserted with one click), set an expiry. " +
    "\"Approved by\" is a plain text field filled in at request time - there's no " +
    "separate in-app approval action for exceptions. The only action afterward is " +
    "Revoke (admin-only, active exceptions only); expiry is automatic."],
  ["How do I approve, reject, or trigger a remediation request?",
    "On Remediation Approvals: findings needing change management appear under " +
    "\"awaiting a request.\" Once requested, a row gets Approve (with an optional real " +
    "AD group-membership check), Reject (with a reason), Mark staging validated (an " +
    "attestation, not a real check), and - once approved - Trigger Remediation, which " +
    "is confirm-gated and spends real API usage to generate the playbook."],
  ["How do I connect a scanner?",
    "Admin only, on Connections: add a connection, pick the source (Tenable, Qualys, " +
    "Prisma Cloud, Cortex XSIAM, Infoblox, Axonius or Active Directory), enter its " +
    "credentials, Test connection, then set a schedule or Sync now. Credentials are " +
    "stored encrypted and never shown again. Each sync is a queued job; a second click " +
    "does not queue another. If scanner credentials must stay out of other systems, have " +
    "the scanner push to Quanta with an API key instead."],
  ["How do I open ServiceNow or Jira tickets automatically for urgent findings?",
    "Add a ServiceNow, Jira Cloud or Splunk connection on Connections (a \"push\" " +
    "connection) and set its rule: minimum severity, KEV only, minimum EPSS, and the " +
    "most tickets per run. Each run opens tickets for matching findings not yet sent, " +
    "most urgent first, never duplicating on a re-run. Ticket state is read back each " +
    "sync."],
  ["How do I create an API key for a scanner, SOAR playbook or CI job?",
    "On Connections, in \"Send data to Quanta\", click Create an API key: name it, tick " +
    "only the access it needs (send findings in, report ticket status, read findings out, report controls, AI usage or SIEM alerts) " +
    "and pick an expiry (never, 30, 90 or 365 days). The key is shown once - copy " +
    "it. Send it as Authorization: Bearer <key>. Revoke in the key table stops it " +
    "immediately."],
  ["How do I import a scanner CSV?",
    "On Connections, \"Import a scanner file\": choose a CSV in the Tenable column " +
    "layout, enter a source name, upload. Tick \"this is the complete export\" only if " +
    "the file is everything that scanner currently reports - it then removes that " +
    "source's findings missing from the file."],
  ["How do I see which ticket belongs to a finding?",
    "Open the finding (click its ID). \"External tickets\" lists tickets a push " +
    "connection opened for it: reference, system, state (Open, In progress, Blocked, " +
    "Resolved) and the last error. State flows back each sync and updates the finding's " +
    "assignment status; a resolved ticket does not close the finding - the next scan " +
    "decides."],
  ["How do I set up scheduled reports or team alerts?",
    "Reports generates on-demand snapshots and has its own \"Schedule automatic email " +
    "reports\" panel. Notification Settings is the fuller surface: the same report-" +
    "schedule config, team alert-subscription rules, a Preview-then-confirm Send-Test " +
    "flow, and a \"Run checks now\" button. Real sending needs SMTP configured " +
    "server-side."],
  ["How is AI Assist different from Ask Quanta?",
    "AI Assist calls the real Claude API (explain/draft remediation/summarize a " +
    "finding, confirm-gated, real cost) - free preview of the prompt if unconfirmed. " +
    "Ask Quanta is free and deterministic: it matches a finding ID/CVE/count/asset " +
    "name, or this FAQ's own entries by keyword overlap. It is explicitly not an LLM " +
    "and not a chatbot - there is no persistent conversational chat interface " +
    "anywhere in this app."],
  ["How do I get step-by-step instructions to fix a finding?",
    "Open the finding and read \"How to fix this\": summary, why it matters, ordered steps, how to " +
    "confirm the fix, what to do if you cannot fix it now, effort and references. It says what it " +
    "matched on and is tailored from what Quanta knows (fixed version, KB number, KEV, EPSS, SLA). " +
    "On Code Scan use the \"How to fix\" button. It changes nothing itself and states what Quanta " +
    "can automate for that finding."],
  ["What does Quanta recommend if I cannot fix a finding right now, and how complete is the guidance?",
    "Each entry lists compensating controls. If the asset's firewall and EDR coverage is recorded in " +
    "security_controls.yaml (ships empty) it shows your real coverage; otherwise it says the controls " +
    "are general. The knowledge base is hand-curated for 29 common classes, not every CWE; unmatched " +
    "findings get a generic approach, labelled generic. Compensating controls reduce risk, they do not " +
    "close the finding."],
  ["How are support tickets prioritised, routed and measured?",
    "Priority is impact times urgency (P1 to P4). Routing rules send a ticket to a team queue; team " +
    "members work it and administrators see everything. Each priority has response and resolution " +
    "targets with at-risk and breached states, and the clock pauses while a ticket waits on the " +
    "requester. Analytics cover SLA compliance, first response, time to resolve, reopen rate, backlog " +
    "age and workload by team, plus satisfaction ratings. A ticket can link to a finding. SLA breaches alert " +
    "the assignee, team manager and admins once per level."],
  ["How do I request a new feature, or report a bug?",
    "Open a ticket from the Support page (type: feature request or bug). It is stored in " +
    "this deployment's own database and triaged by your administrators, who can assign it, " +
    "reply, and optionally escalate it to the vendor by email. Nothing goes to a public tracker."],
  ["What do the scopes on a Quanta API key allow?",
    "ingest:write sends findings, scanner files, SARIF and coverage reports in; " +
    "tickets:update reports ticket status changes; read:findings exports findings; " +
    "controls:write reports security controls an EDR or firewall observes; ai-usage:write " +
    "reports AI usage (gateway events or OpenTelemetry JSON); soc:write sends SIEM or XDR " +
    "alerts for triage. Tick only what a given job needs."],
  ["Does Quanta certify compliance, and what is Risk & Compliance for?",
    "No. Quanta supplies evidence and workflow; it does not certify compliance, and a passing " +
    "test shows that Quanta observed something, not that an auditor would agree. The /grc " +
    "page (admin) maps controls in NIST 800-53 r5, CSF 2.0 and an AI-governance set (built-in " +
    "subsets, or a full catalog you import as OSCAL JSON) to automated tests with thresholds " +
    "in remediation/config/grc_tests.yaml, collected about daily."],
  ["Is the Hunting & SOC page a SIEM? Does it run hunt queries?",
    "No to both. Quanta knows which assets carry exploitable vulnerabilities, so it proposes " +
    "one hunt per open CVE on the CISA KEV list or with EPSS of 0.5 or more, with the hosts, " +
    "the ATT&CK techniques it tags and ready-made queries rendered as Splunk SPL by a small " +
    "translator for Sigma-style selections. You run them in your own SIEM and record each " +
    "result and the hunt's outcome here (closing needs one)."],
  ["How do SOC cases, queues and escalation work?",
    "On the SOC Operations page, a case sits in the L1, L2 or L3 queue. Priority is impact times " +
    "urgency (P1 to P4), and the acknowledge, pickup and resolve clocks come from the targets in " +
    "remediation/config/soc_ops.yaml. Escalating, resolving or closing needs a written summary of at " +
    "least 20 characters, so the next person never starts cold. A case left in a tier past its resolve " +
    "target moves up one tier automatically, with an event saying why. The Metrics tab shows MTTA, " +
    "MTTR, service-level compliance, backlog and how often the first-look recommendation matched the " +
    "analyst's resolution."],
  ["Which models does the SOC tooling use? Is a language model involved?",
    "Almost none. The alert verdict is a weighted score, reports are assembled from stored data, " +
    "technique identification is a Naive Bayes classifier, the playbook recommender is a similarity-" +
    "weighted success rate, and detection use cases come from counting patterns. A language model is " +
    "used only to draft a playbook and to refine a use case, each asked for explicitly, validated, and " +
    "never acted on automatically. The SOC, Hunting and Detection Engineering document gives the method " +
    "for each."],
  ["Where do threat-model threats come from? Is an LLM involved?",
    "From explicit rules you can read in remediation/threatmodel/rules.py, not an LLM. You " +
    "describe a system as components, data flows and trust zones; the rules raise STRIDE " +
    "threats and recompute them on every read, so an edited model never leaves stale threats. " +
    "Each is scored likelihood x impact, with residual risk reduced by recorded control " +
    "coverage, and joined to live findings by ATT&CK technique or CWE overlap."],
  ["How do I see AI spend, and does Quanta read our prompts?",
    "The /ai-usage page (admin) shows tokens and spend by team, application and model, " +
    "budgets, unusual days, cache-hit rate and AI tools nobody reviewed. Quanta stores " +
    "counts, models, times and attribution only, never prompts or responses. Sources: " +
    "Anthropic and OpenAI usage connections (Admin key), gateway events, OpenTelemetry JSON, " +
    "and Quanta's own calls."],
  ["How do I read the guidance on a finding, and does it change by scan type?",
    "Open the finding (click its ID anywhere) and read \"How to fix this\". Guidance is chosen " +
    "from the finding's scan type and its CWE or asset type: code flaws found by static " +
    "analysis (SAST) or by testing a running app (DAST), vulnerable libraries (SCA, with the " +
    "fixed version and upgrade command when known), committed secrets, " +
    "infrastructure-as-code, container images, CI/CD pipeline weaknesses, test-coverage gaps " +
    "in secu"],
  ["How do I bring in SARIF, pipeline or coverage results from my CI?",
    "Create an API key with the ingest:write scope (Connections, \"Send data to Quanta\"), then " +
    "post the file from your pipeline: SARIF 2.1.0 from Semgrep, CodeQL, ZAP, Trivy, Checkov, " +
    "gitleaks and similar tools to POST /api/ingest/sarif; a Cobertura, JaCoCo or lcov report " +
    "to POST /api/ingest/coverage (only security-relevant files become findings)."],
  ["How do I record a security control on an asset?",
    "Admin only. On Security Controls, under \"Add a control\", enter the asset name or a " +
    "pattern such as WEB-*, choose the kind of control (for example EDR, network filtering, " +
    "MFA), describe it in your own words and click Add control. To load many at once, use \"or " +
    "import a CSV\"."],
  ["What do verified, claimed, absent and unknown mean in the compensating-control advice?",
    "In place (verified): a connector or script observed the control on that asset. In place " +
    "(recorded, not verified): a person recorded it. Not in place: controls are recorded for " +
    "the asset but this mitigation is not among them. Not known for this asset: nothing is " +
    "recorded, so Quanta does not guess."],
  ["How do I build a threat model and review its threats?",
    "Admin only. Under \"New model\", name it and start from an editable example, from your " +
    "assets (components drafted from the findings), or empty. Open the model, adjust " +
    "components, data flows and trust zones in the JSON editor (properties you leave out " +
    "count as not recorded) and click Save model."],
  ["How do I import a framework and collect evidence?",
    "Admin only. On Risk & Compliance, open the Controls tab. The built-in catalogs (NIST " +
    "800-53 r5, CSF 2.0 and an AI-governance set) are subsets. To work against every control, " +
    "use \"Import a full catalog\": give it an id and upload the framework's OSCAL JSON (for a " +
    "licensed standard, your licensed copy in OSCAL form). Then open the Evidence tab and " +
    "click Collect evidence now; it also runs about once a day."],
  ["How do I attest to a control Quanta cannot observe?",
    "On the Controls tab of Risk & Compliance, click Attest beside the control, say whether " +
    "it is effective, partially-effective or ineffective, and give the statement it rests on " +
    "(required). The attestation sits beside the automated evidence rather than replacing it, " +
    "and shows as expired when it is no longer current."],
  ["How do I register a risk?",
    "Admin only. Open the Risk register tab. \"Worth registering\" lists suggestions drawn from " +
    "live findings and threat models: click one to add it. Or fill in \"Add a risk\": title, " +
    "owner, likelihood and impact from 1 to 5, a treatment (mitigate, accept, transfer, " +
    "avoid) with the plan or reason, and a review date. The register shows inherent and " +
    "residual level, owner, status and whether a review is overdue."],
  ["How do I start a hunt from a proposal and close it with an outcome?",
    "Admin only. Quanta is not a SIEM and does not run queries; it proposes where to look and " +
    "you run the queries in your own tool. On Proposed hunts, each card is an open CVE that " +
    "is on the KEV list or has an EPSS of 0.5 or more, with the hosts, the ATT&CK techniques " +
    "Quanta tags and ready-made queries (Splunk SPL, to be adapted to your data model)."],
  ["How do I triage a SOC alert?",
    "Alerts reach Quanta from your SIEM or XDR through POST /api/ingest/alerts with an API " +
    "key that has the soc:write scope. On the Alert triage tab they are ranked by a priority " +
    "that reflects what Quanta knows about the host: its owner, open findings, and " +
    "known-exploited ones, with the reasons listed."],
  ["How do I set an AI budget, and see which AI tools nobody reviewed?",
    "Admin only. AI Usage shows tokens and spend by team, application, model and source. " +
    "Quanta stores counts only, never prompts or responses, and the page lists which sources " +
    "are reporting; cost is reported or estimated, and requests of unknown cost are counted " +
    "separately, never shown as zero."],
  ["How do I feed AI usage into Quanta?",
    "Three ways. Add an Anthropic usage or OpenAI usage connection on Connections, using that " +
    "provider's Admin key. Or post events from a gateway or script to POST " +
    "/api/ingest/ai-usage, or send OpenTelemetry JSON to /api/ingest/otlp/v1/traces, with an " +
    "API key that has the ai-usage:write scope. Quanta's own calls are included. See " +
    "docs/INTEGRATION_API.md."],
  ["How does this compare to ServiceNow's Vulnerability Response / USEM module?",
    "The core bet is remediation, not just detection: three separate mechanisms by " +
    "asset domain (Ansible playbooks, a real git-PR flow for app code, and a " +
    "compensating-control-only track for OT/IoT) under one RBAC model, rather than " +
    "one generic 'auto-remediate' button. See docs/enterprise-suite/whitepaper.html " +
    "§02 for the full comparison, including where legacy tools still legitimately win."],
  ["Has Quanta filed for, or been granted, any patents?",
    "No. A patent-landscape review (not a legal opinion) found the broad 'AI generates " +
    "a remediation playbook' concept already claimed by other companies' existing " +
    "patents, so that alone is unlikely to be novel. A couple of narrower angles are " +
    "flagged as worth a real attorney's opinion, not claimed as patentable here - see " +
    "docs/enterprise-suite/whitepaper.html §04."],
  ["What if I find a bug or need help?",
    "See the Support page, or docs/SUPPORT.md in the repo."],
];

export async function render(container) {
  container.innerHTML = `
    <p class="subtitle">Direct answers about what this product does and doesn't do
    today - no marketing language.</p>
    <div class="faq-list">
      ${FAQS.map(([q, a]) => `
        <details class="faq-item">
          <summary>${q}</summary>
          <p>${a}</p>
        </details>`).join("")}
    </div>`;
}
