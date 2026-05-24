"""
Technique Matcher v2.0 — Dynamic KB-driven strategy matching.
No hardcoded strategy lists. All techniques come from KnowledgeBase.match_techniques()
which merges heap_techniques.json + parsed how2heap C sources.
"""

import json
import os
import sys
from typing import Dict, List


class TechniqueMatcher:
    def __init__(self, glibc_version=None, binary_security=None,
                 libc_offsets=None, interface_map=None, esm_hints=None):
        self.glibc_version = glibc_version or "2.39"
        self.binary_security = binary_security or {}
        self.libc_offsets = libc_offsets or {}
        self.interface_map = interface_map or {}
        self.esm_hints = esm_hints or {}

        from core.knowledge_base.loader import get_knowledge_base
        self.kb = get_knowledge_base()

        self.ops = self.interface_map.get("operations", {})
        self._find_available_operations()

    def _find_available_operations(self):
        self.available_ops = set()
        for choice, info in self.ops.items():
            role = info.get("role")
            if role in ("alloc", "free", "view", "edit"):
                self.available_ops.add(role)
        if not self.available_ops:
            self.available_ops = {"alloc", "free", "view", "edit"}

    def extract_bugs_from_esm(self, esm_hints):
        bugs = set()
        if not esm_hints:
            return bugs
        for b in esm_hints.get("detected_bugs", []):
            bugs.add(b)
        return bugs

    def extract_capabilities_from_esm(self, esm_hints):
        caps = set()
        if not esm_hints:
            return caps
        for c in esm_hints.get("detected_capabilities", []):
            caps.add(c)
        return caps

    def detect_bugs_from_interface(self):
        bugs = set()
        for role in ("view", "edit"):
            choice = None
            for c, info in self.ops.items():
                if info.get("role") == role:
                    choice = c
                    break
            if choice:
                free_choice = None
                for c, info in self.ops.items():
                    if info.get("role") == "free":
                        free_choice = c
                        break
                if free_choice:
                    bugs.add("potential_uaf_via_idx")

        free_choice = None
        alloc_choice = None
        for c, info in self.ops.items():
            r = info.get("role")
            if r == "free":
                free_choice = c
            elif r == "alloc":
                alloc_choice = c
        if free_choice and alloc_choice:
            free_steps = self.ops.get(free_choice, {}).get("steps", [])
            alloc_steps = self.ops.get(alloc_choice, {}).get("steps", [])
            has_free_idx = any(s.get("arg") == "idx" for s in free_steps)
            has_alloc_idx = any(s.get("arg") == "idx" for s in alloc_steps)
            if has_free_idx and has_alloc_idx:
                bugs.add("potential_double_free")
        return bugs

    def detect_consolidation_trigger(self):
        for choice, info in self.ops.items():
            steps = info.get("steps", [])
            for s in steps:
                if s.get("type") == "data":
                    return True
        if self.interface_map.get("menu_prompt"):
            return True
        return False

    # ─── Core matching — uses KB ────────────────

    # ─── 3-Factor Context-Aware Strategy Ranking ─────────────────────

    def _has_complex_interface(self) -> bool:
        ops = self.interface_map.get("operations", {})
        total_ops = len(ops)
        if total_ops > 4:
            return True
        role_counts = {}
        for choice, info in ops.items():
            role = info.get("role", "")
            if role:
                role_counts[role] = role_counts.get(role, 0) + 1
        if any(count >= 2 for count in role_counts.values()):
            return True
        return False

    def _get_max_slots(self) -> int:
        """Detect max allocatable slots from binary strings in interface_map."""
        ops = self.interface_map.get("operations", {})
        for choice, info in ops.items():
            if info.get("role") == "alloc":
                steps = info.get("steps", [])
                for s in steps:
                    if s.get("arg") == "idx":
                        hint = s.get("type", "")
                        if "range" in hint.lower() or "0-" in hint:
                            try:
                                parts = hint.split("0-")
                                return int(parts[1].split()[0]) + 1
                            except (IndexError, ValueError):
                                pass
        return 0

    def _esm_mentions_keyword(self, keywords: list) -> bool:
        """
        Check if ESM/NLP writeup extraction contains specific keywords
        (e.g. "botcake", "consolidate", "house_of_botcake").
        Searches across all ESM state technique names and writeup vars.
        """
        esm = self.esm_hints or {}
        for kw in keywords:
            kw_lower = kw.lower()
            # Check in detected_techniques
            for tech_list_key in ("detected_techniques", "techniques"):
                techs = esm.get(tech_list_key, [])
                if isinstance(techs, list):
                    for t in techs:
                        if isinstance(t, str) and kw_lower in t.lower():
                            return True
                        if isinstance(t, dict) and kw_lower in str(t.get("id", "")).lower():
                            return True
                if isinstance(techs, dict):
                    for k, v in techs.items():
                        if kw_lower in k.lower():
                            return True
                        if isinstance(v, dict) and kw_lower in str(v.get("state", "")).lower():
                            return True
            # Check bug/capability lists
            for list_key in ("detected_bugs", "detected_capabilities"):
                items = esm.get(list_key, [])
                for item in items:
                    if kw_lower in str(item).lower():
                        return True
        return False

    def _detect_interface_type(self) -> str:
        """
        Classify interface type for context-aware strategy routing.
        Returns "complex_multi_group" or "simple_crud".
        """
        if self._has_complex_interface():
            return "complex_multi_group"
        slots = self._get_max_slots()
        if slots >= 8:
            return "complex_multi_group"
        return "simple_crud"

    def rank_strategies(self, bugs=None, capabilities=None):
        """
        Rank exploit strategies using 3-factor context-aware decision:
          Factor 1 (KB Match): base confidence from heap_techniques.json
          Factor 2 (NLP Hints)
          Factor 3 (Interface Caps): simple CRUD vs complex multi-group
        Returns list of dicts sorted by confidence descending.
        """
        if bugs is None:
            bugs = set()
        if capabilities is None:
            capabilities = set()

        bugs.update(self.detect_bugs_from_interface())
        available_ops = list(self.available_ops)

        # Detect context
        interface_type = self._detect_interface_type()
        esm_mentions_botcake = self._esm_mentions_keyword(
            ["botcake", "house_of_botcake"]
        )
        esm_mentions_consolidate = self._esm_mentions_keyword(
            ["consolidate", "malloc_consolidate", "consolidation"]
        )

        # Query KB for all matching techniques
        matched = self.kb.match_techniques(
            self.glibc_version, list(bugs), list(capabilities), available_ops
        )

        # Build strategies from KB-matched techniques
        strategies = {}
        for m in matched:
            tech_data = m["technique"]
            tech_id = m["technique_id"]
            produces = tech_data.get("produces", [])
            if isinstance(produces, str):
                produces = [produces]

            strategy_key = self._build_strategy_key(tech_id, produces, matched)

            if strategy_key not in strategies:
                strategies[strategy_key] = {
                    "label": self._build_strategy_label(tech_id, matched),
                    "techniques": [],
                    "requires": list(self.available_ops),
                    "glibc_min": "2.0",
                    "glibc_max": "9.9",
                    "kb_confidence": 0,
                }
            strategies[strategy_key]["techniques"].append(tech_id)
            strategies[strategy_key]["kb_confidence"] = max(
                strategies[strategy_key]["kb_confidence"], m["confidence"]
            )

        # --- 3-Factor Scoring ---
        results = []
        for sk, sv in strategies.items():
            # Factor 1: KB base score
            score = sv["kb_confidence"] * 2

            # Operation completeness bonus
            if all(o in self.available_ops for o in sv.get("requires", [])):
                score += len(sv.get("requires", []))

            # Factor 2: NLP Writeup Hints
            is_house_of_botcake = "house_of_botcake" in sk
            is_consolidate = "malloc_consolidate" in sk or "consolidate" in sk

            if is_house_of_botcake:
                if esm_mentions_botcake:
                    score += 5  # Writeup explicitly mentions botcake → strong boost
                # If writeup does NOT mention botcake, house_of_botcake gets NO bonus
            if is_consolidate:
                if esm_mentions_consolidate:
                    score += 3  # Consolidation mentioned in writeup → moderate boost
                # else: no bonus, consolidation is generic

            # Factor 3: Interface Caps
            if is_house_of_botcake or is_consolidate:
                if interface_type == "complex_multi_group":
                    score += 4  # Complex interface → house_of_botcake/consolidate suitable
                else:
                    score -= 3  # Simple CRUD → penalize consolidation strategies

            # Simple tcache poison: boost for simple interfaces
            is_basic_tcache = sk in ("tcache_poisoning", "tcache_poison_stack")
            if is_basic_tcache and interface_type == "simple_crud":
                score += 8  # Simple CRUD → strongly prefer basic tcache poison

            # Consolidation trigger bonus (if binary supports large sends)
            if self.detect_consolidation_trigger():
                has_consolidate = any(
                    "consolidate" in t.lower() for t in sv["techniques"]
                )
                if has_consolidate:
                    score += 2

            # Leak technique bonus
            has_leak = any("leak" in t.lower() for t in sv["techniques"])
            if has_leak:
                score += 3

            # ROP/control flow bonus
            has_rop = any(
                t in ("rop_chain", "environ_leak") or
                "ret_addr" in t.lower() or "stack" in t.lower()
                for t in sv["techniques"]
            )
            if has_rop:
                score += 4

            confidence = max(0, min(10, score))
            reasons = (
                f"kb:{sv['kb_confidence']}"
                f"_interface:{interface_type}"
                f"_nlp_botcake:{esm_mentions_botcake}"
                f"_nlp_consolidate:{esm_mentions_consolidate}"
            )
            results.append({
                "strategy": sk,
                "label": sv["label"],
                "confidence": confidence,
                "techniques": sv["techniques"],
                "reasons": reasons,
            })

        results.sort(key=lambda r: r["confidence"], reverse=True)
        return results

    def _build_strategy_key(self, tech_id: str, produces: List[str],
                            matched: List[Dict]) -> str:
        """Build a strategy key from technique characteristics."""
        if any("poison" in tech_id.lower() or tc_id in tech_id for tc_id in
               ["tcache_poisoning", "tcache_metadata_poisoning"]):
            if any("environ" in t.get("technique_id", "") for t in matched):
                return "tcache_poison_stack"
            if any(m.get("technique", {}).get("produces", []) == ["arbitrary_write"]
                   for m in matched):
                return "tcache_hooks"
            return "tcache_poisoning"
        if "fastbin" in tech_id.lower():
            return "fastbin_dup"
        if "house_of_botcake" in tech_id.lower():
            return "house_of_botcake"
        if "got" in tech_id.lower() or tech_id == "got_overwrite":
            return "got_overwrite"
        if "unsorted" in tech_id.lower() or "leak" in tech_id.lower():
            return f"{tech_id}_leak"
        if "stack" in tech_id.lower() or "rop" in tech_id.lower():
            return "rop_chain"
        if "environ" in tech_id.lower():
            return "environ_leak"
        if "consolidate" in tech_id.lower():
            return "malloc_consolidate"
        if "safe_linking" in tech_id.lower():
            return "safe_linking_bypass"
        return tech_id

    def _build_strategy_label(self, tech_id: str, matched: List[Dict]) -> str:
        """Build a human-readable label for the strategy."""
        nice_name = tech_id.replace("_", " ").title()
        if any(m.get("technique_id", "").startswith("unsortedbin") for m in matched):
            return f"{nice_name} → Libc Leak"
        if any(m.get("technique_id", "") == "environ_leak" for m in matched):
            return f"{nice_name} → Stack Leak → ROP"
        if any("hook" in m.get("technique_id", "") for m in matched):
            return f"{nice_name} → Hook Overwrite"
        return nice_name

    def get_recommended_strategy(self, bugs=None, capabilities=None):
        ranked = self.rank_strategies(bugs, capabilities)
        if ranked:
            return ranked[0]
        return {"strategy": "tcache_poisoning", "confidence": 0, "techniques": ["tcache_poisoning", "unsortedbin_leak"]}

    def get_technique_chain(self, strategy_name):
        chain_map = {
            "tcache_poison_stack": [
                "decrypt_safe_linking", "unsortedbin_leak",
                "malloc_consolidate_trigger", "tcache_poisoning",
                "environ_leak", "tcache_poisoning"
            ],
            "got_overwrite": ["tcache_poisoning", "unsortedbin_leak"],
            "tcache_hooks": ["unsortedbin_leak", "tcache_poisoning"],
            "fastbin_dup": ["unsortedbin_leak", "fastbin_dup"],
            "house_of_botcake": [
                "decrypt_safe_linking", "house_of_botcake",
                "unsortedbin_leak", "tcache_poisoning"
            ],
        }
        # KB-based: get from matched techniques
        if strategy_name not in chain_map:
            return [strategy_name]
        return chain_map.get(strategy_name, [strategy_name])

    def print_report(self, bugs=None, capabilities=None):
        if bugs is None:
            bugs = {"uaf"}
        if capabilities is None:
            capabilities = set()

        print("=" * 60)
        print("  TECHNIQUE MATCHER REPORT (KB-driven)")
        print("=" * 60)
        print(f"  glibc: {self.glibc_version}")
        print(f"  operations: {', '.join(sorted(self.available_ops))}")
        print(f"  detected bugs: {', '.join(sorted(bugs)) if bugs else 'none'}")
        print(f"  detected caps: {', '.join(sorted(capabilities)) if capabilities else 'none'}")
        print("-" * 60)

        ranked = self.rank_strategies(bugs, capabilities)
        for r in ranked:
            if r["confidence"] > 0:
                print(f"  [{r['confidence']}/10] {r['label']}")
                print(f"       techniques: {', '.join(r['techniques'])}")
                print(f"       reasons: {r['reasons']}")
        print("=" * 60)
        return ranked


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--glibc", default="2.39")
    parser.add_argument("--bugs", nargs="*", default=["uaf"])
    parser.add_argument("--interface", default=None)
    args = parser.parse_args()

    interface_map = {}
    if args.interface and os.path.exists(args.interface):
        with open(args.interface) as f:
            interface_map = json.load(f)

    matcher = TechniqueMatcher(
        glibc_version=args.glibc,
        interface_map=interface_map
    )
    matcher.print_report(bugs=set(args.bugs))
