"""
Module 4: Composite ESM Analyzer (Rewritten)

Implements the Exploitation State Machine with support for:
1. Composite ESM: merge multiple ESMs from different traces/writeups
2. State Equivalence Query (EQ): compare states for matching
3. Action Query (AQ): find applicable actions from a state
4. Enhanced latent capability inference
5. Evidence binding from trace events
"""

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Tuple

@dataclass
class Chunk:
    addr: int
    size: int
    status: str = "allocated"  # allocated, free
    fd: Optional[int] = None
    bk: Optional[int] = None
    content: bytes = b""
    history: List[dict] = field(default_factory=list)

@dataclass
class ESMState:
    """A state in the Exploitation State Machine."""
    bugs: Dict[str, str] = field(default_factory=dict)        # name -> "detected" | "unknown"
    primitives: Dict[str, str] = field(default_factory=dict)
    techniques: Dict[str, str] = field(default_factory=dict)
    capabilities: Dict[str, str] = field(default_factory=dict)
    goals: Dict[str, str] = field(default_factory=dict)
    latent_capabilities: Dict[str, dict] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "bugs": self.bugs,
            "primitives": self.primitives,
            "techniques": self.techniques,
            "capabilities": self.capabilities,
            "goals": self.goals,
            "latent_capabilities": self.latent_capabilities,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ESMState":
        return cls(
            bugs=d.get("bugs", {}),
            primitives=d.get("primitives", {}),
            techniques=d.get("techniques", {}),
            capabilities=d.get("capabilities", {}),
            goals=d.get("goals", {}),
            latent_capabilities=d.get("latent_capabilities", {}),
        )


class ESMAnalyzer:
    def __init__(self, critical_data: dict):
        self.critical_data = critical_data

        # Support both old format (single taxonomy) and new composite format
        if "composite_taxonomy" in critical_data:
            self.taxonomy = critical_data.get("composite_taxonomy", {})
            self.exploit_ir = critical_data.get("composite_exploit_ir", {})
        else:
            self.taxonomy = critical_data.get("taxonomy", {})
            self.exploit_ir = critical_data.get("exploit_ir", {})

        self.chunks: Dict[int, Chunk] = {}
        self.esm_states: List[dict] = []

        # Evidence Binding
        self.detected_bugs: Dict[str, List[dict]] = {}
        self.detected_primitives: Dict[str, List[dict]] = {}
        self.detected_techniques: Dict[str, List[dict]] = {}
        self.detected_capabilities: Dict[str, List[dict]] = {}
        self.detected_goals: Dict[str, List[dict]] = {}

        # Composite ESM support
        self.action_catalog: List[dict] = []  # All generalized actions
        self.state_transitions: List[dict] = []  # (from_state, action, to_state)

        # Pre-populate detected items from NLP composite taxonomy
        self._init_from_nlp_taxonomy()

    def _init_from_nlp_taxonomy(self):
        """Initialize detected capabilities from NLP composite taxonomy."""
        # Use a synthetic event for NLP-derived detections
        nlp_event = {"seq": 0, "type": "NLP", "note": "composite_writeup_analysis"}

        for bug in self.taxonomy.get("bugs", []):
            self._bind_evidence("bugs", bug, nlp_event)
        for prim in self.taxonomy.get("primitives", []):
            self._bind_evidence("primitives", prim, nlp_event)
        for tech in self.taxonomy.get("techniques", []):
            self._bind_evidence("techniques", tech, nlp_event)
        for cap in self.taxonomy.get("capabilities", []):
            self._bind_evidence("capabilities", cap, nlp_event)
        for goal in self.taxonomy.get("goals", []):
            self._bind_evidence("goals", goal, nlp_event)

    def _bind_evidence(self, category: str, name: str, event: dict):
        store = {
            "bugs": self.detected_bugs,
            "primitives": self.detected_primitives,
            "techniques": self.detected_techniques,
            "capabilities": self.detected_capabilities,
            "goals": self.detected_goals
        }.get(category)

        if store is not None:
            if name not in store:
                store[name] = []
            if event.get("seq") not in [e.get("seq") for e in store[name]]:
                store[name].append(event)

    def _infer_latent_capabilities(self) -> dict:
        latent = {}

        # 1. Potential Stack Leak
        if ("libc_leak" in self.detected_capabilities or
            "arbitrary_allocation" in self.detected_primitives):
            if ("arbitrary_write" in self.detected_primitives or
                "arbitrary_allocation" in self.detected_primitives):
                if "stack_leak" not in self.detected_capabilities:
                    latent["stack_leak"] = {
                        "state": "potential_latent",
                        "reason": "Presence of libc_leak/arbitrary_alloc allows targeting __environ for stack leak."
                    }

        # 2. Potential Control Flow Hijack
        if ("arbitrary_write" in self.detected_primitives or
            "tcache_poisoning" in self.detected_techniques):
            if ("stack_leak" in self.detected_capabilities or
                "libc_leak" in self.detected_capabilities):
                if "control_flow_hijack" not in self.detected_goals:
                    latent["control_flow_hijack"] = {
                        "state": "potential_latent",
                        "reason": "Arbitrary write/poisoning + known target address enables hijacking."
                    }

        # 3. Potential Arbitrary Allocation (from tcache struct overwrite)
        if "tcache_perthread_struct" in self.taxonomy.get("structures", []):
            if "arbitrary_allocation" not in self.detected_primitives:
                latent["arbitrary_allocation_via_tcache_struct"] = {
                    "state": "potential_latent",
                    "reason": "Tcache struct knowledge enables arbitrary allocation without poisoning."
                }

        return latent

    def _get_state(self) -> ESMState:
        def format_store(store, keys):
            res = {}
            for k in keys:
                if k in store:
                    res[k] = {
                        "state": "detected",
                        "evidence_count": len(store[k]),
                        "evidence": store[k]
                    }
                else:
                    res[k] = {"state": "unknown"}
            return res

        return ESMState(
            bugs=format_store(self.detected_bugs, self.taxonomy.get("bugs", [])),
            primitives=format_store(self.detected_primitives, self.taxonomy.get("primitives", [])),
            techniques=format_store(self.detected_techniques, self.taxonomy.get("techniques", [])),
            capabilities=format_store(self.detected_capabilities, self.taxonomy.get("capabilities", [])),
            goals=format_store(self.detected_goals, self.taxonomy.get("goals", [])),
            latent_capabilities=self._infer_latent_capabilities()
        )

    # ─── State Equivalence Query (EQ) ────────────────────────────────
    @staticmethod
    def state_eq(s1: ESMState, s2: ESMState) -> bool:
        """Check if two ESM states are equivalent (paper Section III-C)."""
        for attr in ["bugs", "primitives", "techniques", "capabilities", "goals"]:
            d1 = getattr(s1, attr, {})
            d2 = getattr(s2, attr, {})
            # Compare detected keys
            detected1 = {k for k, v in d1.items() if v.get("state") == "detected"}
            detected2 = {k for k, v in d2.items() if v.get("state") == "detected"}
            if detected1 != detected2:
                return False
        return True

    # ─── Action Query (AQ) ───────────────────────────────────────────
    def action_query(self, state: ESMState) -> List[dict]:
        """Given a state, return all possible actions (paper Section III-C)."""
        actions = []
        detected_caps = {k for k, v in state.capabilities.items() if v.get("state") == "detected"}
        detected_prims = {k for k, v in state.primitives.items() if v.get("state") == "detected"}
        detected_techs = {k for k, v in state.techniques.items() if v.get("state") == "detected"}

        transitions = self.exploit_ir.get("transitions", [])
        for t in transitions:
            # Check if the "from" condition is satisfied
            from_key = t["from"]
            if from_key in detected_caps or from_key in detected_prims or from_key in detected_techs:
                actions.append({
                    "action": t["action"],
                    "target_state": t["to"],
                    "confidence": t.get("confidence", 0.5)
                })

        # Sort by confidence (most popular first, as per paper)
        actions.sort(key=lambda a: a["confidence"], reverse=True)
        return actions

    def process_events(self, events: List[dict]):
        """Process trace events and build ESM state timeline."""
        print(f"[*] Processing {len(events)} events with Evidence Binding...")

        for ev in events:
            etype = ev.get("type", "")
            addr_str = ev.get("addr", "0x0")
            addr = int(addr_str, 16)
            size = ev.get("size", 0)
            note = ev.get("note", "").lower()

            # 1. Update Heap Model
            if etype == "Alloc":
                self.chunks[addr] = Chunk(addr=addr, size=size, status="allocated")
                self.chunks[addr].history.append(ev)

                if "target_libc_hijack" in note:
                    self._bind_evidence("primitives", "arbitrary_allocation", ev)
                    self._bind_evidence("capabilities", "libc_leak", ev)
                if "target_stack_hijack" in note:
                    self._bind_evidence("primitives", "arbitrary_allocation", ev)

            elif etype == "Free":
                if addr in self.chunks:
                    if self.chunks[addr].status == "free":
                        self._bind_evidence("bugs", "double_free", ev)
                    self.chunks[addr].status = "free"
                    self.chunks[addr].history.append(ev)
                else:
                    if addr != 0:
                        self._bind_evidence("primitives", "arbitrary_free", ev)

            elif etype in ("Read", "Write", "Leak", "Copy"):
                target_chunk = self._find_target_chunk(addr)

                if target_chunk and target_chunk.status == "free":
                    self._bind_evidence("bugs", "uaf", ev)

                if etype in ("Read", "Write", "Copy") and target_chunk:
                    if addr + size > target_chunk.addr + target_chunk.size:
                        self._bind_evidence("bugs", "overflow", ev)

                if etype in ("Read", "Write") and target_chunk and target_chunk.status == "free":
                    if addr == target_chunk.addr:
                        self._bind_evidence("techniques", "tcache_poisoning", ev)
                        self._bind_evidence("primitives", "arbitrary_write", ev)

                if etype == "Leak" or etype == "Read":
                    if "libc_ptr_candidate" in note:
                        self._bind_evidence("capabilities", "libc_leak", ev)
                    if "heap_ptr_candidate" in note:
                        self._bind_evidence("capabilities", "heap_leak", ev)
                    if "stack_ptr_candidate" in note or "target_stack_hijack" in note:
                        self._bind_evidence("capabilities", "stack_leak", ev)

                if etype in ("Write", "Read", "Copy"):
                    if "target_stack_hijack" in note:
                        self._bind_evidence("primitives", "arbitrary_write", ev)
                        self._bind_evidence("goals", "control_flow_hijack", ev)
                    if "target_libc_hijack" in note:
                        self._bind_evidence("primitives", "arbitrary_write", ev)

            # 2. Update State Machine
            state_after = self._get_state()
            self.esm_states.append({
                "seq": ev.get("seq"),
                "event": ev,
                "state_after": state_after.to_dict()
            })

    def _find_target_chunk(self, addr: int) -> Optional[Chunk]:
        for c_addr, chunk in self.chunks.items():
            if c_addr <= addr < c_addr + chunk.size:
                return chunk
        return None

    def _build_chunk_table(self) -> dict:
        table = {}
        for addr, chunk in self.chunks.items():
            table[hex(addr)] = {
                "size": chunk.size,
                "status": chunk.status,
                "fd": hex(chunk.fd) if chunk.fd else None,
                "bk": hex(chunk.bk) if chunk.bk else None,
            }
        return table

    def _collect_leak_info(self) -> list:
        leaks = []
        for entry in self.esm_states:
            ev = entry.get("event", {})
            note = ev.get("note", "")
            if "libc_ptr_candidate" in note or "heap_ptr_candidate" in note:
                leak_info = {
                    "seq": ev.get("seq"),
                    "type": ev.get("type"),
                    "addr": ev.get("addr"),
                    "content": ev.get("content", ""),
                    "note": note,
                    "heap_chunk_ref": ev.get("heap_chunk_ref"),
                }
                if "unsorted_bin_leak" in note:
                    leak_info["leak_type"] = "unsorted_bin"
                elif "heap_leak" in note:
                    leak_info["leak_type"] = "heap"
                else:
                    leak_info["leak_type"] = "unknown"
                leaks.append(leak_info)
        return leaks

    # ─── Composite ESM Merge ─────────────────────────────────────────
    @staticmethod
    def merge_esms(esm1: dict, esm2: dict) -> dict:
        """Merge two ESM outputs into a composite ESM (paper Section III-B.3)."""
        merged_states = esm1.get("esm_states", []) + esm2.get("esm_states", [])
        merged_chunk_table = {**esm1.get("chunk_table", {}), **esm2.get("chunk_table", {})}
        merged_leak_info = esm1.get("leak_info", []) + esm2.get("leak_info", [])

        # Deduplicate states by seq
        seen_seqs = set()
        unique_states = []
        for s in merged_states:
            seq = s.get("seq")
            if seq not in seen_seqs:
                seen_seqs.add(seq)
                unique_states.append(s)

        return {
            "esm_states": unique_states,
            "chunk_table": merged_chunk_table,
            "leak_info": merged_leak_info,
            "merged_from": 2
        }

    def save_results(self, output_file: str):
        print("\n" + "=" * 60)
        print("  AutoPwn – ESM Reasoner Summary (Deep Inference)")
        print("=" * 60)

        st = self._get_state()
        for cat in ["bugs", "primitives", "techniques", "capabilities", "goals"]:
            detected = [k for k, v in getattr(st, cat).items() if v.get("state") == "detected"]
            if detected:
                print(f" [+] {cat.upper():<12}: {', '.join(detected)}")

        latent = st.latent_capabilities
        if latent:
            print(f" [?] LATENT      : {', '.join(latent.keys())}")
            for k, v in latent.items():
                print(f"     -> {k}: {v['reason']}")
        print("=" * 60)

        output = {
            "esm_states": self.esm_states,
            "chunk_table": self._build_chunk_table(),
            "leak_info": self._collect_leak_info(),
            "action_catalog": self.action_catalog,
            "state_transitions": self.state_transitions,
        }
        with open(output_file, "w") as f:
            json.dump(output, f, indent=4)
        print(f"\n[OK] Deep ESM analysis saved to {output_file}")


if __name__ == "__main__":
    critical_path = "../artifacts/critical_vars.json"
    trace_path = "../artifacts/trace_events.json"
    output_path = "../artifacts/esm_output.json"

    if not (os.path.exists(critical_path) and os.path.exists(trace_path)):
        print("[!] Missing input files.")
        exit(1)

    with open(critical_path, "r") as f:
        critical_data = json.load(f)

    with open(trace_path, "r") as f:
        events = json.load(f)

    analyzer = ESMAnalyzer(critical_data)
    analyzer.process_events(events)
    analyzer.save_results(output_path)
