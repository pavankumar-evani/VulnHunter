# Ontology, provenance and multi-hop questions

Quanta already draws one relationship graph per module (`remediation/graphs/`). The ontology layer (`remediation/ontology/`) adds four things on top of
that data without changing what any builder decides is connected:

1. a **vocabulary** (`remediation/config/ontology.yaml`): the classes of thing Quanta records and the typed relations between them;
2. a **conformance check** of any graph against that vocabulary;
3. **provenance**: where each link came from, when it was seen and how sure that is, wherever stored data says so;
4. a **question engine**: bounded, typed multi-hop path queries over one whole-estate graph, plus named questions an administrator can run.

Nothing here stores data of its own, trains a model, or contacts anything. It reads what is already recorded.

## 1. The vocabulary

`ontology.yaml` has three parts, each described in the file's header.

- **classes**: `Thing` at the root, then `Asset`, `Application`, `Component` (with `Package` and `ModelComponent`), `Finding`, `Vulnerability`, `Technique`,
  `Control`, `ControlRequirement`, `Team`, `Person`, `Alert`, `Case`, `Hunt`, `Playbook`, `AIAsset` (an `Asset`), `Model`, `Tool` (with `McpServer`),
  `DataSource`, `Risk`, `Framework` (a `Policy`) and others. Each has one parent (`is_a`), one plain sentence, optional **attributes** a question may filter on
  (bool, string, number or enum) and optional **required** attributes.
- **relations**: each has a sentence and `signatures` (`domain` to `range`). `affects: Finding -> Asset`, `runs: Asset -> Application`,
  `depends-on: Application|Component -> Component`, `exploits: Vulnerability -> Component`, `mitigates: Control -> Technique`, `owns: Team|Person -> Asset`,
  `reaches: Asset -> Asset` (and network hops), `invokes: AIAsset -> Tool`, and so on. Axioms: **transitive** (`depends-on`, `reaches`), **inverse pairs**
  (`owns`/`owned-by`, `affects`/`affected-by`, `mitigates`/`mitigated-by`, `runs`/`runs-on`, `depends-on`/`depended-on-by`), **sub-relation**
  (`routes-to` is a kind of `reaches`) and **cardinalities** (`affects`: every finding has exactly one asset; `instance-of`: at most one vulnerability).
- **mappings**: how each module graph's own node and edge kinds read as classes and relations (a SOC `host` is an `Asset`, a devsecops `uses` edge is
  `depends-on`). A kind with no entry is reported, never guessed.

The file is checked when it loads (unknown parent, signature naming an unknown class, a one-way inverse, a mapping onto something undeclared, a missing
description are all hard errors), so everything else can rely on it. To teach Quanta a new kind of thing, add a class or relation, add the mapping, and the
validator and question engine pick it up.

## 2. Validation (`validate.py`)

`validate(graph)` returns a SHACL-like report: `conforms`, counts per rule and a list of violations, each naming the offending **node or edge** and the
**rule**: `unknown-class`, `unknown-relation`, `domain-range`, `required-attribute`, `attribute-type`, `cardinality`, `dangling-edge`,
`invalid-provenance`. It never changes or drops anything it reads. Minimum cardinalities are skipped for a graph its builder truncated (a missing edge may be
one that was cut) and the report says so. The report is capped at 500 listed violations; the counts are not.

## 3. Provenance (`provenance.py`, `graphs/schema.py`)

`GraphBuilder.node` and `.edge` accept an optional `prov=` (`source`, `source_kind`, `observed_at`, `confidence`). The key appears in the output **only** when
a builder passed it, so existing graphs are byte-for-byte unchanged. `source_kind` is `connector`, `scan`, `user` or `derived`; `confidence` is `observed`,
`declared` (recorded by a person or file, not independently seen) or `heuristic` (inferred by a rule that can be wrong).

Builders attach it where stored data says it: the supply-chain graph carries the SBOM's upload time and source on every `uses`/`depends_on` link; SOC alerts carry
their source and occurrence time; ownership and assignment links say they are declared; topology links are `user`/`declared`; attack-chain pivots are
`derived`/`heuristic`; AI register links are `user`/`declared` and usage-derived links carry the event's source and time. The estate graph adds the finding's
source and last-seen date, a control's source and last-seen date (verified is `connector`/`observed`, claimed is `user`/`declared`) and marks name-matched
links (`exploits`) heuristic.

`provenance.facts(graph)` is the **Fact view**: every edge as (subject, relation, object) with the four fields and an `unknown` list. A field the data does not
say is `None`; it is never defaulted to the current time, the module or a confident-sounding value. `coverage()` reports how much is known.

## 4. The estate graph and questions (`estate.py`, `query.py`)

`estate.build()` reads every module graph through the mappings, joins nodes that are the same thing (an asset by name, a team, a person, a technique, a
package), and adds from stored data: a `Finding` per queue finding (capped at 1,500, most severe first) linked to its asset, to a `Vulnerability` when it has a
CVE (KEV and EPSS only when enrichment recorded them), to ATT&CK techniques already on it and, by package name, to an SBOM `Package`; and the controls inventory
as `Control` nodes that `protect` assets their pattern matches and `mitigate` the techniques their class addresses. Three Asset facts are computed from the graph
and listed in `meta.derived`: `internet_facing` (a path from an Internet node through `reaches`), `owned` (an `owns` or `assigned-to` edge) and
`verified_controls`. Each is left **unset** where nothing covers the asset. The graph is capped at 2,500 nodes, each node keeps `origin` (module, id) so a result
can be drawn back on its module graph, and a module whose builder fails is listed under `sources` rather than failing the whole.

A **pattern** is JSON, never free text:

```json
{"start": {"class": "Asset", "where": [{"attr": "internet_facing", "op": "eq", "value": true}]},
 "steps": [{"relation": "runs", "to": {"class": "Application"}},
           {"relation": "depends-on", "repeat": "star", "max_depth": 4, "to": {"class": "Component"}},
           {"relation": "exploits", "direction": "in", "to": {"class": "Vulnerability", "where": [{"attr": "kev", "op": "eq", "value": true}]}}],
 "limit": 50}
```

read as `Asset(internet_facing = true) -runs-> Application -depends-on*-> Component <-exploits- Vulnerability(kev = true)`. It is parsed against the ontology
before anything runs: classes, relations and attributes must exist, values must fit the declared type, each hop must be one the relation's signatures allow, and
unknown keys are refused. There is no expression language and no regular expression (`contains` is a plain, case-insensitive substring test). Caps: 8 steps,
depth 6, 8 conditions per node, 200 results, 250,000 units of work, 5,000 partial paths; a capped result says so. A class matches its subclasses; a relation also
follows its special cases; an inverse name is the original read backwards. A repeated step returns the shortest path to each node it reaches. An attribute that is
not recorded is unknown and satisfies no condition, not even `ne`; use `exists: false` to ask for "not recorded".

An empty result always carries a **reason**: which stage matched nothing, and whether the data simply does not record what was asked ("none of the 1 Tool
nodes records side_effects"). Each returned path carries the Fact for every edge.

`config/ontology_questions.yaml` holds the named questions (internet-facing assets that reach a KEV-listed vulnerability with no verified control; findings on
unowned assets; applications that reach a KEV vulnerability through their dependencies; AI tools with write side effects reachable from untrusted data
sources; internet-facing assets carrying a KEV vulnerability). Each states its limits. They are checked against the ontology when listed; one an edit broke is
shown with its error rather than dropped.

## Routes and page

| Route | Who | What |
|---|---|---|
| `GET /api/ontology` | anyone (like other reads) | the vocabulary and mappings |
| `GET /api/ontology/questions` | anyone | named questions, normalised patterns, one-line text |
| `GET /api/ontology/validate[?module=]` | administrator | every module graph and the estate graph checked, plus provenance coverage |
| `POST /api/ontology/query` | administrator | body `{"pattern": {...}}` or `{"question": "<id>"}`; 400 with the reason for a bad pattern |

Licensing: `/api/ontology` is a *shared* prefix in `licensing.yaml` (any one licensed module is enough), like `/api/graphs`. The **Ontology** section sits under
the graph on the existing Relationship graphs page (no new nav entry): "Check conformance" shows the validation status and provenance coverage, and the question
picker runs a named question and lights its result paths on the module graph being viewed (through each node's `origin`), listing the steps that live in other modules.

## Honest limits

- Quanta's AI register does not record a tool's side effects or a data source's trust level, so the AI question returns nothing until records carry `side_effects`
  and `trust`. It says so.
- `internet_facing` needs network topology or firewall data; `verified_controls = 0` means none recorded as verified, not none present; KEV needs the enrichment.
- Asset to application links are not invented: the estate graph has no `runs` edge between hosts and applications because no stored data says which runs which.
- A name match (finding dependency to SBOM package) is marked heuristic.
- The estate graph is built per request from the module builders (administrator only); there is no cache, and it inherits each builder's own 400-node cap.
- This is a conformance check and a path query, not an OWL reasoner or a SPARQL store; transitivity is followed by the query's `star`/`plus`, not materialised.
- The Ontology section of the Graphs page was exercised through Node (path-to-graph mapping) and the API tests; it has not been click-tested in a browser in this change.
