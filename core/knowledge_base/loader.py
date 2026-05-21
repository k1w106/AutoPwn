"""
Knowledge Base Loader for AutoPwn v3.0

Loads structured knowledge from data/knowledge/ and data/ontologies/
to provide reasoning rules, constraints, and validation for exploit planning.
"""

import json
import os
from typing import Dict, List, Any, Optional


class KnowledgeBase:
    """Central knowledge base for heap exploitation reasoning."""

    def __init__(self, root_dir: str = None):
        if root_dir is None:
            root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        self.knowledge_dir = os.path.join(root_dir, "data", "knowledge")
        self.ontology_dir = os.path.join(root_dir, "data", "ontologies")

        self.malloc_internals: Dict = {}
        self.heap_structures: Dict = {}
        self.mitigations: Dict = {}
        self.ontology: Dict = {}

        self._load_all()

    def _load_all(self):
        """Load all knowledge files."""
        self.malloc_internals = self._load_json("malloc_internals.json")
        self.heap_structures = self._load_json("heap_structures.json")
        self.mitigations = self._load_json("mitigations.json")
        self.ontology = self._load_json("heap_exploit_taxonomy.json", self.ontology_dir)

    def _load_json(self, filename: str, directory: str = None) -> Dict:
        """Load a JSON file from knowledge directory."""
        dir_path = directory or self.knowledge_dir
        path = os.path.join(dir_path, filename)
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
        return {}

    # ─── Malloc Internals Queries ────────────────────────────────────

    def get_tcache_info(self) -> Dict:
        """Get tcache behavior rules."""
        return self.malloc_internals.get("tcache", {})

    def get_unsorted_bin_info(self) -> Dict:
        """Get unsorted bin behavior rules."""
        return self.malloc_internals.get("unsorted_bin", {})

    def get_free_checks(self) -> Dict:
        """Get all free() validation checks."""
        return self.malloc_internals.get("free_checks", {})

    def get_malloc_checks(self) -> Dict:
        """Get all malloc() validation checks."""
        return self.malloc_internals.get("malloc_checks", {})

    def get_fake_chunk_rules(self) -> Dict:
        """Get rules for creating fake chunks."""
        return self.malloc_internals.get("fake_chunk_rules", {})

    def get_version_info(self, version: str = None) -> Dict:
        """Get glibc version-specific changes."""
        if version:
            return self.malloc_internals.get("version_specific_changes", {}).get(version, {})
        return self.malloc_internals.get("version_specific_changes", {})

    # ─── Validation Rules ────────────────────────────────────────────

    def validate_fake_chunk_size(self, size: int, purpose: str = "unsorted_bin") -> tuple:
        """
        Validate if a fake chunk size is appropriate for the given purpose.
        Returns (is_valid, reason).
        """
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
        """
        Validate a sequence of free/alloc actions against malloc rules.
        Returns (is_valid, issues).
        """
        issues = []
        tcache_max = self.get_tcache_info().get("max_per_size", 7)

        # Track frees per size class
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
                        "issue": f"Tcache for size {hex(size_class)} is full ({tcache_max} entries), next free will go to unsorted bin",
                        "severity": "INFO"
                    })

        return len(issues) == 0, issues

    def check_mitigations(self, glibc_version: str = None) -> List[Dict]:
        """
        Get active mitigations for a given glibc version.
        """
        active = []
        version_changes = self.get_version_info()

        if glibc_version:
            major_minor = ".".join(glibc_version.split(".")[:2])
            for ver, change in version_changes.items():
                if ver <= major_minor:
                    active.append({"version": ver, "change": change})

        # Check specific mitigations
        mitigations = self.mitigations
        if "safe_linking" in mitigations:
            active.append({
                "name": "safe_linking",
                "description": mitigations["safe_linking"].get("description", ""),
                "bypass": mitigations["safe_linking"].get("bypass", {})
            })

        if "tcache_double_free_detection" in mitigations:
            active.append({
                "name": "tcache_double_free_detection",
                "description": mitigations["tcache_double_free_detection"].get("description", ""),
                "bypass": mitigations["tcache_double_free_detection"].get("bypass", {})
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
        """Get the standard exploit phases."""
        return self.ontology.get("exploit_phases", {})

    def get_bug_to_primitive_mapping(self) -> Dict:
        """Get mapping from bug types to exploit primitives."""
        return self.ontology.get("bug_to_primitive_mapping", {})

    def get_technique_requirements(self, technique: str) -> Dict:
        """Get requirements for a specific technique."""
        return self.ontology.get("technique_requirements", {}).get(technique, {})

    def get_capability_chain(self) -> Dict:
        """Get the full exploit capability chain."""
        return self.ontology.get("capability_chain", {})

    def get_decision_rules(self) -> Dict:
        """Get decision rules for technique selection."""
        return self.ontology.get("decision_rules", {})

    # ─── Reasoning Helpers ───────────────────────────────────────────

    def suggest_technique(self, bug_type: str, constraints: Dict = None) -> List[Dict]:
        """
        Suggest exploitation techniques based on bug type and constraints.
        """
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

    def validate_exploit_chain(self, chain: List[str]) -> tuple:
        """
        Validate if an exploit chain is complete and logically sound.
        Returns (is_valid, missing_steps).
        """
        full_chain = self.get_capability_chain().get("full_exploit", {})
        typical_path = full_chain.get("typical_path", [])

        missing = []
        for step in typical_path:
            if step not in chain:
                missing.append(step)

        return len(missing) == 0, missing


# Singleton instance
_kb_instance = None

def get_knowledge_base(root_dir: str = None) -> KnowledgeBase:
    """Get or create the global knowledge base instance."""
    global _kb_instance
    if _kb_instance is None:
        _kb_instance = KnowledgeBase(root_dir)
    return _kb_instance
