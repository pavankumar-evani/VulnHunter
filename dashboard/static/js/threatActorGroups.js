// Mirrors remediation/enrichment/threat_actor_groups.py's THREAT_ACTOR_GROUPS on the
// client side, same "small hardcoded reference list mirrored in JS" pattern already
// used by infraTypes.js/scanTypes.js - see that module's docstring for the
// zero-fabrication verification this data went through (each id/name/alias/technique
// list checked directly against attack.mitre.org/groups/ during implementation) and the
// "illustrative cross-reference, not an attribution claim" caveat that applies here too.
//
// `status`/`mostRecentActivity` and `targetIndustries` were added and independently
// re-verified against each group's live MITRE page on 2026-08-05 - see the Python
// module's own docstring for the full sourcing/honesty notes (every group here is
// currently ACTIVE per MITRE, not retired; a group missing an industry tag genuinely has
// no sector-specific victimology documented for it today, not an oversight).
export const INDUSTRIES = [
  "Financial Services & Banking",
  "Capital Markets",
  "Insurance",
  "Healthcare",
  "Retail & Consumer",
  "Government & Defense",
  "Energy & Utilities",
  "Technology & Telecom",
  "Education",
  "Media & Entertainment",
  "Transportation & Logistics",
  "Hospitality",
];

export const THREAT_ACTOR_GROUPS = [
  {
    id: "G0007", name: "APT28",
    aliases: ["Fancy Bear", "Sofacy", "Sednit", "Pawn Storm", "STRONTIUM", "Forest Blizzard"],
    mitreUrl: "https://attack.mitre.org/groups/G0007/",
    summary: "Russian state-sponsored group attributed to the GRU, active since at least 2004 - cyber espionage against government, military, and political targets, including the 2016 DNC/DCCC compromises.",
    associatedTechniqueIds: ["T1566", "T1110", "T1003", "T1021", "T1083", "T1059", "T1105", "T1090"],
    targetIndustries: ["Government & Defense", "Hospitality"],
    status: "active",
    mostRecentActivity: "APT28 Nearest Neighbor Campaign (Feb 2022 - Nov 2024)",
  },
  {
    id: "G0016", name: "APT29",
    aliases: ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard", "Dark Halo"],
    mitreUrl: "https://attack.mitre.org/groups/G0016/",
    summary: "Russian state-sponsored group attributed to the SVR, active since at least 2008 - the 2015 DNC compromise and the 2020-2021 SolarWinds software supply-chain compromise.",
    associatedTechniqueIds: ["T1566", "T1087", "T1059", "T1098", "T1190", "T1078"],
    targetIndustries: ["Government & Defense", "Technology & Telecom"],
    status: "active",
    mostRecentActivity: "Documented activity through at least 2024 (government, cloud/IT supply-chain targeting)",
  },
  {
    id: "G0032", name: "Lazarus Group",
    aliases: ["Labyrinth Chollima", "HIDDEN COBRA", "ZINC", "Diamond Sleet"],
    mitreUrl: "https://attack.mitre.org/groups/G0032/",
    summary: "North Korean state-sponsored group attributed to the Reconnaissance General Bureau, active since at least 2009 - responsible for the 2014 Sony Pictures Entertainment attack.",
    associatedTechniqueIds: ["T1566", "T1071", "T1059", "T1087", "T1083", "T1041", "T1547", "T1105"],
    targetIndustries: ["Financial Services & Banking", "Media & Entertainment", "Government & Defense", "Energy & Utilities"],
    status: "active",
    mostRecentActivity: "Operation Dream Job (Sep 2019 - Aug 2020); ongoing per MITRE's most recent page update",
  },
  {
    id: "G0046", name: "FIN7",
    aliases: ["Carbon Spider", "ITG14", "Sangria Tempest", "ELBRUS"],
    mitreUrl: "https://attack.mitre.org/groups/G0046/",
    summary: "Financially-motivated group active since 2013 - point-of-sale malware against retail/restaurant/financial-services targets, later big-game-hunting ransomware operations.",
    associatedTechniqueIds: ["T1566", "T1059", "T1486", "T1021", "T1087", "T1105", "T1078", "T1547"],
    targetIndustries: [
      "Retail & Consumer", "Financial Services & Banking", "Healthcare", "Hospitality",
      "Technology & Telecom", "Media & Entertainment", "Transportation & Logistics", "Energy & Utilities",
    ],
    status: "active",
    mostRecentActivity: "Documented targeting the United States automotive industry (Apr 2024)",
  },
  {
    id: "G0034", name: "Sandworm Team",
    aliases: ["Voodoo Bear", "Telebots", "Seashell Blizzard", "APT44"],
    mitreUrl: "https://attack.mitre.org/groups/G0034/",
    summary: "Destructive group attributed to Russia's GRU unit 74455, active since at least 2009 - Ukrainian power-grid attacks (2015, 2016, 2022) and the 2017 NotPetya ransomware attack.",
    associatedTechniqueIds: ["T1566", "T1105", "T1485", "T1078", "T1570", "T1059", "T1021"],
    targetIndustries: ["Energy & Utilities", "Government & Defense", "Transportation & Logistics", "Technology & Telecom"],
    status: "active",
    mostRecentActivity: "2022 Ukraine Electric Power Attack",
  },
  {
    id: "G0096", name: "APT41",
    aliases: ["Wicked Panda", "Brass Typhoon", "BARIUM"],
    mitreUrl: "https://attack.mitre.org/groups/G0096/",
    summary: "Chinese state-sponsored espionage group that also conducts financially-motivated operations, active since at least 2012 - targets healthcare, telecom, technology, finance, education, retail, and video-game industries.",
    associatedTechniqueIds: ["T1566", "T1190", "T1105", "T1059", "T1087", "T1003", "T1021"],
    targetIndustries: [
      "Healthcare", "Technology & Telecom", "Financial Services & Banking",
      "Education", "Retail & Consumer", "Media & Entertainment",
    ],
    status: "active",
    mostRecentActivity: "APT41 DUST campaign (Jan 2023 - Jun 2024)",
  },
];

// Returns [{...group, findingCount, matchedTechniqueIds}] for every group with at least
// one associated technique already present in `findings`' attack_techniques - sorted by
// findingCount descending. A group absent from the result simply has none of its known
// techniques in this dataset today (same "real, not padded" honesty as every other
// zero-count taxonomy in this app).
export function correlateFindings(findings) {
  const countsByTechnique = new Map();
  for (const f of findings) {
    for (const t of f.attack_techniques || []) {
      if (!t.technique_id) continue;
      countsByTechnique.set(t.technique_id, (countsByTechnique.get(t.technique_id) || 0) + 1);
    }
  }

  const results = [];
  for (const group of THREAT_ACTOR_GROUPS) {
    const matched = group.associatedTechniqueIds.filter((tid) => countsByTechnique.has(tid));
    if (!matched.length) continue;
    const findingCount = matched.reduce((sum, tid) => sum + countsByTechnique.get(tid), 0);
    results.push({ ...group, findingCount, matchedTechniqueIds: matched });
  }
  results.sort((a, b) => b.findingCount - a.findingCount);
  return results;
}

// Returns the actual finding objects (not just a count) that share at least one of
// `group`'s known ATT&CK techniques - used by the group-detail modal (groupDetail.js)
// to show real assets/owners/findings/remediation-status for one group's overlap with
// this tenant's current data. Accepts either a raw THREAT_ACTOR_GROUPS entry or a
// correlateFindings() result (which already carries the narrower matchedTechniqueIds).
export function findingsForGroup(group, findings) {
  const techniqueIds = new Set(group.matchedTechniqueIds || group.associatedTechniqueIds);
  return findings.filter((f) => (f.attack_techniques || []).some((t) => techniqueIds.has(t.technique_id)));
}
