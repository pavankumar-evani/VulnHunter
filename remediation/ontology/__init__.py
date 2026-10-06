"""An ontology, provenance and multi-hop question layer over the relationship graphs Quanta already builds (see docs/ONTOLOGY.md).

ontology.py   the vocabulary (remediation/config/ontology.yaml): classes, is-a, typed relations, axioms, and how each module graph maps onto it
validate.py   a SHACL-like check of a graph against the vocabulary; reports violations, never changes or drops data
provenance.py the Fact view: where each edge came from, when it was seen, how sure that is; unknown stays unknown
estate.py     one whole-estate graph assembled from the module builders plus findings and recorded controls, in ontology terms
query.py      a bounded, typed multi-hop path query over the estate graph, and the named questions in config/ontology_questions.yaml
"""
