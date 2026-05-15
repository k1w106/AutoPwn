import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any

@dataclass
class Chunk:
    addr: int
    size: int
    status: str = "allocated" # allocated, free
    fd: Optional[int] = None
    bk: Optional[int] = None
    content: bytes = b""
    history: List[dict] = field(default_factory=list)

class ESMAnalyzer:
    def __init__(self, critical_data: dict):
        self.critical_data = critical_data
        self.taxonomy = critical_data.get("taxonomy", {})
        self.exploit_ir = critical_data.get("exploit_ir", {})
        
        self.chunks: Dict[int, Chunk] = {}
        self.esm_states: List[dict] = []
        
        # Evidence Binding: {primitive_name: [list_of_events]}
        self.detected_bugs: Dict[str, List[dict]] = {}
        self.detected_primitives: Dict[str, List[dict]] = {}
        self.detected_techniques: Dict[str, List[dict]] = {}
        self.detected_capabilities: Dict[str, List[dict]] = {}
        self.detected_goals: Dict[str, List[dict]] = {}
        
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
            if event["seq"] not in [e["seq"] for e in store[name]]:
                store[name].append(event)

    def _infer_latent_capabilities(self):
        latent = {}
        
        # 1. Potential Stack Leak
        if "libc_leak" in self.detected_capabilities or "arbitrary_allocation" in self.detected_primitives:
            if "arbitrary_write" in self.detected_primitives or "arbitrary_allocation" in self.detected_primitives:
                if "stack_leak" not in self.detected_capabilities:
                    latent["stack_leak"] = {
                        "state": "potential_latent",
                        "reason": "Presence of libc_leak/arbitrary_alloc allows targeting __environ for stack leak."
                    }
        
        # 2. Potential Control Flow Hijack
        if "arbitrary_write" in self.detected_primitives or "tcache_poisoning" in self.detected_techniques:
            if "stack_leak" in self.detected_capabilities or "libc_leak" in self.detected_capabilities:
                if "control_flow_hijack" not in self.detected_goals:
                    latent["control_flow_hijack"] = {
                        "state": "potential_latent",
                        "reason": "Arbitrary write/poisoning + known target address enables hijacking."
                    }

        return latent

    def _get_state(self):
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

        state = {
            "bugs": format_store(self.detected_bugs, self.taxonomy.get("bugs", [])),
            "primitives": format_store(self.detected_primitives, self.taxonomy.get("primitives", [])),
            "techniques": format_store(self.detected_techniques, self.taxonomy.get("techniques", [])),
            "capabilities": format_store(self.detected_capabilities, self.taxonomy.get("capabilities", [])),
            "goals": format_store(self.detected_goals, self.taxonomy.get("goals", [])),
            "latent_capabilities": self._infer_latent_capabilities()
        }
        return state

    def process_events(self, events: List[dict]):
        print(f"[*] Processing {len(events)} events with Evidence Binding...")
        
        for ev in events:
            etype = ev["type"]
            addr = int(ev["addr"], 16)
            size = ev.get("size", 0)
            note = ev.get("note", "").lower()

            # 1. Update Heap Model
            if etype == "Alloc":
                self.chunks[addr] = Chunk(addr=addr, size=size, status="allocated")
                self.chunks[addr].history.append(ev)
                
                if "target_libc_hijack" in note:
                    self._bind_evidence("primitives", "arbitrary_allocation", ev)
                    self._bind_evidence("capabilities", "libc_leak", ev) # If we allocated in libc, we know libc base
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
                "state_after": state_after
            })

    def _find_target_chunk(self, addr: int) -> Optional[Chunk]:
        for c_addr, chunk in self.chunks.items():
            if c_addr <= addr < c_addr + chunk.size:
                return chunk
        return None

    def save_results(self, output_file: str):
        print("\n" + "="*60)
        print("  AutoPwn – ESM Reasoner Summary (Deep Inference)")
        print("="*60)
        
        st = self._get_state()
        for cat in ["bugs", "primitives", "techniques", "capabilities", "goals"]:
            detected = [k for k, v in st[cat].items() if v["state"] == "detected"]
            if detected:
                print(f" [+] {cat.upper():<12}: {', '.join(detected)}")
        
        latent = st["latent_capabilities"]
        if latent:
            print(f" [?] LATENT      : {', '.join(latent.keys())}")
            for k, v in latent.items():
                print(f"     -> {k}: {v['reason']}")
        print("="*60)

        with open(output_file, "w") as f:
            json.dump(self.esm_states, f, indent=4)
        print(f"\n[OK] Deep ESM analysis saved to {output_file}")

if __name__ == "__main__":
    critical_path = "module3/critical_vars.json"
    trace_path = "module3/trace_events.json"
    output_path = "module4/esm_output.json"

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
