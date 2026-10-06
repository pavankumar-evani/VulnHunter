# Simulated connectors

Quanta is meant to run on real data from real connectors. For demonstrations, evaluations and tests it can also run **simulated connectors**: the demonstration data travels the same path as live data instead of sitting in a committed file.

## How it works

A fictional, deterministic estate (`remediation/simulation/estate.py`: a dozen hosts by default, real public CVE ids, no real organisation or person) is rendered into each vendor's **real response format** and replayed through the connector's own code over the `session=` seam every connector already has. Request building, paging, parsing, `scanner_csv`, classification, merge, KEV and EPSS enrichment all run for real. Only the network is replaced. So connecting a real account later changes the connection from `simulation` to `live` and nothing downstream.

Covered: Tenable, Qualys, OpenVAS, Prisma Cloud, Cortex XSIAM, Infoblox, Axonius, Active Directory (computers), and the Anthropic and OpenAI usage connectors. The same hosts appear in several sources, so correlation, ownership and attack-chain pages have something to show.

## Provenance and safety

- Every record carries `source_mode` (`live` or `simulation`); the Connections page and the finding detail show a **Simulated** tag.
- A simulated record never overwrites a live one; live data replaces a simulated record when it arrives.
- **Simulation is refused when `QUANTA_ENV=prod`** unless an operator sets `QUANTA_ALLOW_SIMULATION=true` (a hosted demonstration site), and the page then shows a "SIMULATED DATA ENABLED" strip.
- A simulation connection holds no credentials and does no network or DNS check.
- Removal deletes only simulated records: `python cli/quanta_admin.py seed-demo --remove`, or `DELETE /api/simulation`.

## Using it

```bash
python cli/quanta_admin.py seed-demo            # creates "Simulated <name>" connections and runs them through the real sync
python cli/quanta_admin.py seed-demo --remove   # removes them and only their records
```

In the app: Connections, "Load demonstration data" (administrator; previews first, then confirm). The routes are `GET /api/simulation/status`, `POST /api/simulation/load` (a preview unless `confirm`) and `DELETE /api/simulation`.

## Adding a connector

Write `render_<name>(estate, values)` in `remediation/simulation/renderers.py` returning a `ReplaySession` (or the injectable client the connector uses), render responses FROM THE ESTATE in the vendor's real format (read the connector and its tests for the exact shapes), honour paging, add it to `RENDERERS` and `LABELS`, and test that a full `sync.run` of a simulation connection yields schema-valid records with `source_mode == "simulation"`.

## Honest limits

It proves Quanta's parsing, correlation and workflows, not that a vendor's live service behaves the same today. The responses follow each vendor's published formats as the connectors parse them, and no connector has been run against a live account. Active Directory users and groups are not simulated (the connector reads computers only); Prisma Cloud and Axonius pull a single page, as their connectors do.
