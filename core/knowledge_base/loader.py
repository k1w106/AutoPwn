"""
Knowledge Base Loader for AutoPwn v3.0

Loads structured knowledge from data/knowledge/, data/ontologies/,
and parsed how2heap C sources to provide reasoning rules, constraints,
and validation for exploit planning.
"""

import json
import os
import sys
from typing import Dict, List, Any, Optional, Set, Tuple


class KnowledgeBase:
    """Central knowledge base for heap exploitation reasoning."""

    def __init__(self, root_dir: str = None):
        if root_dir is None:
            root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        self.root_dir = root_dir
        self.knowledge_dir = os.path.join(root_dir, "data", "knowledge")
        self.ontology_dir = os.path.join(root_dir, "data", "ontologies")

        # Static knowledge (JSON)
        self.malloc_internals: Dict = {}
        self.heap_structures: Dict = {}
        self.mitigations: Dict = {}
        self.ontology: Dict = {}
        self.heap_techniques: Dict = {}
        self.how2heap_techniques: List[Dict] = []
        self.parsed_techniques: List[Dict] = []

        self._load_all()

    def _load_all(self):
        """Load all knowledge files."""
        self.malloc_internals = self._load_json("malloc_internals.json")
        self.heap_structures = self._load_json("heap_structures.json")
        self.mitigations = self._load_json("mitigations.json")
        self.ontology = self._load_json("heap_exploit_taxonomy.json", self.ontology_dir)
        self.heap_techniques = self._load_json("heap_techniques.json")

        # Load parsed how2heap techniques
        self._load_how2heap()

    def _load_json(self, filename: str, directory: str = None) -> Dict:
        """Load a JSON file from knowledge directory."""
        dir_path = directory or self.knowledge_dir
        path = os.path.join(dir_path, filename)
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
        return {}

    def _load_how2heap(self):
        """Load parsed how2heap techniques from cache or parse on demand."""
        cache_path = os.path.join(self.root_dir, "data", "parsed_techniques.json")
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "r") as f:
                    data = json.load(f)
                self.parsed_techniques = data.get("techniques", [])
                return
            except Exception:
                pass

        # Parse on demand
        try:
            sys.path.insert(0, os.path.join(self.root_dir, "core"))
            from parser.how2heap_parser import parse_all
            data = parse_all()
            self.parsed_techniques = data.get("techniques", [])
        except Exception:
            self.parsed_techniques = []

    def _get_json_techniques(self) -> List[Dict]:
        """Get technique definitions from heap_techniques.json."""
        return self.heap_techniques.get("techniques", [])

    def _normalize_version(self, ver: str) -> Tuple[int, int]:
        """Normalize a version string like '2.34' to (2, 34)."""
        try:
            parts = ver.split(".")
            return (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
        except (ValueError, IndexError):
            return (0, 0)

    def _version_in_range(self, target: str, min_ver: str, max_ver: str) -> bool:
        """Check if target version is within [min_ver, max_ver]."""
        tv = self._normalize_version(target)
        minv = self._normalize_version(min_ver)
        maxv = self._normalize_version(max_ver)
        return minv <= tv <= maxv

    def _has_bug(self, technique: Dict, required_bugs: Set[str]) -> bool:
        """Check if any of the technique's required bugs are in the detected set."""
        tech_bugs = set()
        for src in ["bug_types", "bug_type"]:
            raw = technique.get(src, technique.get("prerequisites", {}).get("bugs", []))
            if isinstance(raw, str):
                tech_bugs.update(b.strip().lower() for b in raw.replace(" OR ", ",").split(","))
            elif isinstance(raw, list):
                tech_bugs.update(b.lower() for b in raw if isinstance(b, str))
        prereq_bugs = technique.get("prerequisites", {}).get("bugs", [])
        if isinstance(prereq_bugs, list):
            tech_bugs.update(b.lower() for b in prereq_bugs)

        if not tech_bugs:
            return True
        return bool(tech_bugs & required_bugs)

    # ─── match_techniques — Reasoning Engine ──────────────────────────

    def match_techniques(
        self,
        target_glibc_version: str,
        detected_bugs: List[str],
        detected_capabilities: List[str] = None,
        available_ops: List[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Reasoning engine: filter + rank techniques.

        Filters:
          1. glibc version compatibility (min <= target <= max)
          2. bug requirements satisfied (detected_bugs contains what technique needs)
          3. operation requirements satisfied (available_ops)

        Ranks by:
          - Fewer total prerequisite bugs satisfied → lower is better?
            Actually priority: matching = higher score
          - Stability: tcache > fastbin > unsorted bin (encoded in scoring)
          - Simpler (fewer required operations) = higher rank
        """
        if detected_capabilities is None:
            detected_capabilities = []
        if available_ops is None:
            available_ops = ["alloc", "free", "view", "edit"]

        bug_set = set(b.lower() for b in detected_bugs)
        cap_set = set(c.lower() for c in detected_capabilities)
        op_set = set(available_ops)

        # Score weights per technique id prefix
        stability_weights = {
            "tcache": 5,
            "fastbin": 4,
            "unsorted": 3,
            "large_bin": 2,
            "unsafe": 2,
            "house_of": 3,
        }

        candidates = []

        # 1. Evaluate from heap_techniques.json
        for tech in self._get_json_techniques():
            result = self._evaluate_technique(
                tech, tech.get("id", ""), target_glibc_version,
                bug_set, cap_set, op_set, stability_weights
            )
            if result:
                candidates.append(result)

        # 2. Evaluate from parsed how2heap
        for tech in self.parsed_techniques:
            tech_id = tech.get("id", "")
            # Skip if we already have a JSON version with higher confidence
            existing = {c["technique_id"] for c in candidates}
            if tech_id in existing:
                continue

            # Build version range
            ver_info = tech.get("glibc_versions", {})
            min_ver = ver_info.get("min", tech.get("glibc_dir_version", "2.0"))
            max_ver = ver_info.get("max", tech.get("glibc_dir_version", "9.9"))

            # Build bugs from parsed data
            bugs = tech.get("bug_types", ["uaf"])

            # Estimate required ops from heap_operations
            ops = set()
            for hop in tech.get("heap_operations", []):
                hop_op = hop.get("op", "")
                if hop_op == "ALLOC":
                    ops.add("alloc")
                elif hop_op == "FREE":
                    ops.add("free")
                elif hop_op == "OVERWRITE":
                    ops.add("edit")

            combined = {
                "id": tech_id,
                "name": tech_id.replace("_", " ").title(),
                "glibc_versions": {"min": min_ver, "max": max_ver},
                "bug_type": " OR ".join(bugs) if bugs else "uaf",
                "prerequisites": {
                    "bugs": bugs,
                    "capabilities": [],
                    "operations": list(ops) if ops else ["alloc", "free"],
                },
                "produces": ["arbitrary_allocation"],
                "phase": "phase_2_primitive",
                "pattern_hints": {
                    "observable_trace": tech.get("description", ""),
                    "required_operations": f"ops={list(ops)}",
                },
                "_source": "how2heap",
                "_heap_operations": tech.get("heap_operations", []),
            }

            result = self._evaluate_technique(
                combined, tech_id, target_glibc_version,
                bug_set, cap_set, op_set, stability_weights
            )
            if result:
                result["technique"]["_how2heap_ops"] = tech.get("heap_operations", [])
                candidates.append(result)

        # Sort by confidence descending
        candidates.sort(key=lambda c: c["confidence"], reverse=True)
        return candidates

    def _evaluate_technique(
        self,
        tech: Dict,
        tech_id: str,
        target_ver: str,
        bug_set: Set[str],
        cap_set: Set[str],
        op_set: Set[str],
        stability_weights: Dict[str, int],
    ) -> Optional[Dict[str, Any]]:
        """Evaluate a single technique against constraints. Returns score dict or None."""
        ver_info = tech.get("glibc_versions", {})
        min_ver = ver_info.get("min", "2.0")
        max_ver = ver_info.get("max", "9.9")

        if not self._version_in_range(target_ver, min_ver, max_ver):
            return None

        prereqs = tech.get("prerequisites", {})
        req_bugs = prereqs.get("bugs", [])
        if isinstance(req_bugs, str):
            req_bugs = [b.strip() for b in req_bugs.replace(" OR ", ",").split(",")]

        req_ops = prereqs.get("operations", [])
        req_caps = prereqs.get("capabilities", [])
        produces = tech.get("produces", [])

        # Check bug match (OR semantics: any matching bug is sufficient)
        if req_bugs:
            has_bug = any(b.lower() in bug_set for b in req_bugs)
            if not has_bug:
                return None

        # Check operation requirements (AND semantics: all needed ops)
        if req_ops:
            if not all(o in op_set for o in req_ops):
                return None

        # Check capability prerequisites
        if req_caps:
            if not all(c.lower() in cap_set for c in req_caps):
                return None

        # Scoring
        score = 5  # base

        # Stability bonus
        for prefix, weight in stability_weights.items():
            if tech_id.startswith(prefix):
                score += weight
                break

        # Simpler is better: fewer required ops → higher score
        score += max(0, 4 - len(req_ops))

        # Bug match bonus
        bug_match_count = sum(1 for b in req_bugs if b.lower() in bug_set)
        score += bug_match_count * 2

        # Version match bonus (closer to middle is better)
        tv = self._normalize_version(target_ver)
        minv = self._normalize_version(min_ver)
        maxv = self._normalize_version(max_ver)
        if minv < tv < maxv:
            score += 2
        elif tv == minv or tv == maxv:
            score += 1

        confidence = min(10, max(0, score))

        return {
            "technique_id": tech_id,
            "technique": tech,
            "confidence": confidence,
            "reasons": {
                "version_range": f"{min_ver}-{max_ver}",
                "bugs_matched": list(req_bugs),
                "ops_available": req_ops,
                "produces": produces,
            },
            "phase": tech.get("phase", "phase_2_primitive"),
        }

    def suggest_technique(self, bug_type: str, constraints: Dict = None) -> List[Dict]:
        """Suggest exploitation techniques based on bug type and constraints."""
        constraints = constraints or {}
        suggestions = []
        bug_mapping = self.get_bug_to_primitive_mapping().get(bug_type, {})
        techniques = bug_mapping.get("techniques", [])
        for tech in techniques:
            requirements = self.get_technique_requirements(tech)
            if requirements:
                suggestions.append({
                    "technique": tech,
                    "requirements": requirements,
                    "produces": requirements.get("produces", "unknown")
                })
        return suggestions

    # ─── Malloc Internals Queries ────────────────────────────────────

    def get_tcache_info(self) -> Dict:
        return self.malloc_internals.get("tcache", {})

    def get_unsorted_bin_info(self) -> Dict:
        return self.malloc_internals.get("unsorted_bin", {})

    def get_free_checks(self) -> Dict:
        return self.malloc_internals.get("free_checks", {})

    def get_malloc_checks(self) -> Dict:
        return self.malloc_internals.get("malloc_checks", {})

    def get_fake_chunk_rules(self) -> Dict:
        return self.malloc_internals.get("fake_chunk_rules", {})

    def get_version_info(self, version: str = None) -> Dict:
        if version:
            return self.malloc_internals.get("version_specific_changes", {}).get(version, {})
        return self.malloc_internals.get("version_specific_changes", {})

    # ─── Validation Rules ────────────────────────────────────────────

    def validate_fake_chunk_size(self, size: int, purpose: str = "unsorted_bin") -> tuple:
        if purpose == "unsorted_bin":
            tcache_max = self.get_tcache_info().get("max_size", 0x410)
            if size <= tcache_max:
                return False, f"Size {hex(size)} <= tcache max {hex(tcache_max)}, will go to tcache not unsorted bin"
            if size & 0xf != 0:
                return False, f"Size {hex(size)} not aligned to 0x10"
            if size < 0x20:
                return False, f"Size {hex(size)} < minimum chunk size 0x20"
            return True, f"Size {hex(size)} > tcache max {hex(tcache_max)}, will go to unsorted bin"
        elif purpose == "fastbin":
            if size < 0x20 or size > 0x80:
                return False, f"Size {hex(size)} not in fastbin range (0x20-0x80)"
            if size & 0xf != 0:
                return False, f"Size {hex(size)} not aligned to 0x10"
            return True, f"Size {hex(size)} in fastbin range"
        return True, "No validation rules for this purpose"

    def validate_free_sequence(self, actions: List[Dict]) -> tuple:
        issues = []
        tcache_max = self.get_tcache_info().get("max_per_size", 7)
        free_counts = {}
        for action in actions:
            op = action.get("op", "")
            size = action.get("size", 0)
            if op == "FREE":
                size_class = (size + 0xf) & ~0xf if size else 0x30
                free_counts[size_class] = free_counts.get(size_class, 0) + 1
                if free_counts[size_class] > tcache_max:
                    issues.append({
                        "action": action,
                        "issue": f"Tcache for size {hex(size_class)} is full ({tcache_max} entries)",
                        "severity": "INFO"
                    })
        return len(issues) == 0, issues

    def check_mitigations(self, glibc_version: str = None) -> List[Dict]:
        active = []
        version_changes = self.get_version_info()
        if glibc_version:
            major_minor = ".".join(glibc_version.split(".")[:2])
            for ver, change in version_changes.items():
                if ver <= major_minor:
                    active.append({"version": ver, "change": change})
        mitigations = self.mitigations
        for key in ["safe_linking", "tcache_double_free_detection"]:
            if key in mitigations:
                active.append({
                    "name": key,
                    "description": mitigations[key].get("description", ""),
                    "bypass": mitigations[key].get("bypass", {})
                })
        if "hook_removal" in mitigations:
            active.append({
                "name": "hook_removal",
                "description": mitigations["hook_removal"].get("description", ""),
                "alternatives": mitigations["hook_removal"].get("alternatives", [])
            })
        return active

    # ─── Ontology Queries ────────────────────────────────────────────

    def get_exploit_phases(self) -> Dict:
        return self.ontology.get("exploit_phases", {})

    def get_bug_to_primitive_mapping(self) -> Dict:
        return self.ontology.get("bug_to_primitive_mapping", {})

    def get_technique_requirements(self, technique: str) -> Dict:
        return self.ontology.get("technique_requirements", {}).get(technique, {})

    def get_capability_chain(self) -> Dict:
        return self.ontology.get("capability_chain", {})

    def get_decision_rules(self) -> Dict:
        return self.ontology.get("decision_rules", {})

    def validate_exploit_chain(self, chain: List[str]) -> tuple:
        full_chain = self.get_capability_chain().get("full_exploit", {})
        typical_path = full_chain.get("typical_path", [])
        missing = [step for step in typical_path if step not in chain]
        return len(missing) == 0, missing


# Singleton instance
_kb_instance = None


def get_knowledge_base(root_dir: str = None) -> KnowledgeBase:
    global _kb_instance
    if _kb_instance is None:
        _kb_instance = KnowledgeBase(root_dir)
    return _kb_instance
