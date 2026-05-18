"""
Module 3: Operation Generalizer (NEW — matches Paper Algorithm 1)

Generalizes concrete memory operations from trace events into symbolic actions.
Replaces concrete addresses with symbolic values:
  - leak_obj: heap chunk read during exploit (for leaking info)
  - victim_obj: heap chunk overwritten by attacker (for modifying pointers)
  - placeholder_obj: other chunks used for heap layout

Replaces concrete sizes with range scopes based on heap bin:
  - fastbin: (0x18, 0x80)
  - tcache: (0x18, 0x410)
  - unsorted_bin: (0x78, +∞)
  - smallbin: (0x80, 0x400)
  - largebin: (0x400, +∞)
"""

import json
import os
import argparse
from typing import List, Dict, Optional, Any

# Range scopes for different heap bins (from paper Appendix B.B)
BIN_RANGES = {
    "fastbin":      {"min": 0x18, "max": 0x80,  "symbolic": "(0x18, 0x80)"},
    "tcache":       {"min": 0x18, "max": 0x410, "symbolic": "(0x18, 0x410)"},
    "unsorted_bin": {"min": 0x78, "max": None,  "symbolic": "(0x78, +∞)"},
    "smallbin":     {"min": 0x80, "max": 0x400, "symbolic": "(0x80, 0x400)"},
    "largebin":     {"min": 0x400, "max": None, "symbolic": "(0x400, +∞)"},
}

# NPVars: non-program-specific variables (shared across programs)
NPVARS = {
    "__malloc_hook", "__free_hook", "__realloc_hook", "__environ",
    "main_arena", "got", "plt", "_rtld_global", "link_map",
    "tcache_perthread_struct"
}


def classify_bin(size: int) -> str:
    """Classify a chunk size into the appropriate heap bin."""
    if size < 0x80:
        return "fastbin"
    elif size <= 0x410:
        return "tcache"
    elif size <= 0x400:
        return "smallbin"
    else:
        return "largebin"


def get_bin_range(size: int) -> dict:
    """Get the symbolic range for a given chunk size."""
    bin_name = classify_bin(size)
    return BIN_RANGES[bin_name]


def is_npvar(addr: int, heap_base: int, libc_base: int = 0) -> bool:
    """Check if an address is a non-program-specific variable."""
    # tcache struct is at heap_base + 0x10 (after chunk header)
    # and occupies ~0x290 bytes. Only addresses in this exact range are NPVars.
    if heap_base:
        tcache_start = heap_base + 0x10
        tcache_end = tcache_start + 0x290
        if tcache_start <= addr < tcache_end:
            return True
    return False


class OperationGeneralizer:
    """Implements Algorithm 1 from the AutoPwn paper."""

    def __init__(self, events: List[dict], critical_vars: dict = None):
        self.events = events
        self.critical_vars = critical_vars or {}
        self.generalized_actions: List[dict] = []
        self.symbolic_objects: Dict[str, dict] = {}  # leak_obj, victim_obj, placeholder_obj
        self.chunk_map: Dict[int, str] = {}  # addr -> symbolic name
        self.heap_base: Optional[int] = None

    def _find_heap_base(self) -> Optional[int]:
        """Estimate heap base from the first allocation.
        
        The first user allocation is typically after the tcache struct.
        tcache struct is ~0x290 bytes, so heap_base = first_alloc - 0x2a0.
        """
        for ev in self.events:
            if ev.get("type") == "Alloc" and ev.get("addr"):
                addr = int(ev["addr"], 16)
                # First user alloc is typically at heap_base + 0x2a0
                # (0x10 for tcache chunk header + 0x290 for tcache struct + 0x10 for first chunk header)
                # Actually: tcache chunk at heap_base (size 0x291), user data at heap_base+0x10
                # First user chunk at heap_base+0x290 (header), user data at heap_base+0x2a0
                self.heap_base = addr - 0x2a0
                return self.heap_base
        return None

    def _find_chunk_for_addr(self, addr: int) -> Optional[int]:
        """Find the chunk address that contains the given address."""
        for ev in self.events:
            if ev.get("type") == "Alloc" and ev.get("addr"):
                chunk_addr = int(ev["addr"], 16)
                size = ev.get("size", 0)
                if chunk_addr <= addr < chunk_addr + size:
                    return chunk_addr
        return None

    def _assign_symbolic_value(self, addr: int, op_type: str) -> str:
        """Assign a symbolic value to an address based on operation type."""
        chunk_addr = self._find_chunk_for_addr(addr)
        if chunk_addr is None:
            return "placeholder_obj"

        if chunk_addr in self.chunk_map:
            return self.chunk_map[chunk_addr]

        if op_type == "Read" or op_type == "Leak":
            sym = "leak_obj"
        elif op_type == "Write":
            sym = "victim_obj"
        else:
            sym = "placeholder_obj"

        self.chunk_map[chunk_addr] = sym
        self.symbolic_objects[sym] = {
            "chunk_addr": hex(chunk_addr),
            "offset": addr - chunk_addr,
            "first_seen_at": len(self.generalized_actions)
        }
        return sym

    def _generalize_operation(self, op: dict) -> dict:
        """Generalize a single operation (Algorithm 1, Line 3-10, 19-29)."""
        gen_op = dict(op)
        op_type = op.get("type", "")
        addr_str = op.get("addr", "0x0")
        addr = int(addr_str, 16)
        size = op.get("size", 0)

        # Skip NPVar addresses (already symbolic)
        if is_npvar(addr, self.heap_base or 0):
            gen_op["symval"] = addr_str
            gen_op["symsize"] = None
            return gen_op

        # Assign symbolic value based on operation type
        if op_type in ("Read", "Leak"):
            symval = self._assign_symbolic_value(addr, op_type)
            gen_op["symval"] = symval
            if symval == "leak_obj":
                gen_op["symval_detail"] = f"{symval}.fd" if op_type == "Leak" else symval
        elif op_type == "Write":
            symval = self._assign_symbolic_value(addr, op_type)
            gen_op["symval"] = symval
            if symval == "victim_obj":
                gen_op["symval_detail"] = f"{symval}.fd"
        elif op_type == "Alloc":
            # Alloc returns a new chunk; assign placeholder initially
            symval = "placeholder_obj"
            gen_op["symval"] = symval
            # Replace size with range scope
            if size > 0:
                bin_range = get_bin_range(size)
                gen_op["symsize"] = bin_range["symbolic"]
                gen_op["bin_class"] = classify_bin(size)
        elif op_type == "Free":
            chunk_addr = self._find_chunk_for_addr(addr)
            if chunk_addr and chunk_addr in self.chunk_map:
                gen_op["symval"] = self.chunk_map[chunk_addr]
            else:
                gen_op["symval"] = "placeholder_obj"
        else:
            gen_op["symval"] = "placeholder_obj"

        return gen_op

    def _correlation_analysis(self) -> List[dict]:
        """Forward correlation analysis (Algorithm 1, Line 18-29)."""
        # First pass: identify leak_obj and victim_obj
        for ev in self.events:
            gen_op = self._generalize_operation(ev)
            self.generalized_actions.append(gen_op)

        # Second pass: mark remaining as placeholders and resolve sizes
        for i, op in enumerate(self.generalized_actions):
            if "symval" not in op or op["symval"] is None:
                op["symval"] = "placeholder_obj"

            # Resolve placeholder sizes based on relationship with leak/victim objects
            if op.get("type") == "Alloc" and "symsize" not in op:
                size = op.get("size", 0)
                if size > 0:
                    # Check if size matches leak_obj or victim_obj size
                    for sym_name, sym_info in self.symbolic_objects.items():
                        if sym_name in ("leak_obj", "victim_obj"):
                            chunk_addr = int(sym_info["chunk_addr"], 16)
                            # Find the alloc event for this chunk
                            for ev in self.events:
                                if ev.get("type") == "Alloc":
                                    ev_addr = int(ev["addr"], 16)
                                    if ev_addr == chunk_addr:
                                        ev_size = ev.get("size", 0)
                                        if abs(size - ev_size) < 0x10:
                                            op["symsize"] = f"{sym_name}.size"
                                            break

        return self.generalized_actions

    def generalize(self) -> dict:
        """Run the full generalization pipeline."""
        self._find_heap_base()
        actions = self._correlation_analysis()

        # Build summary
        summary = {
            "total_operations": len(actions),
            "symbolic_objects": self.symbolic_objects,
            "chunk_map": {hex(k): v for k, v in self.chunk_map.items()},
            "heap_base": hex(self.heap_base) if self.heap_base else None,
        }

        return {
            "generalized_actions": actions,
            "summary": summary,
            "metadata": {
                "algorithm": "Algorithm 1 from AutoPwn paper",
                "symbolic_values": ["leak_obj", "victim_obj", "placeholder_obj"],
                "bin_ranges": BIN_RANGES,
            }
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Module 3 — Operation Generalizer")
    parser.add_argument("--trace", default="../artifacts/trace_events.json")
    parser.add_argument("--critical", default="../artifacts/critical_vars.json")
    parser.add_argument("--output", default="../artifacts/generalized_actions.json")
    args = parser.parse_args()

    if not os.path.exists(args.trace):
        print(f"[!] Missing trace file: {args.trace}")
        exit(1)

    with open(args.trace, "r") as f:
        events = json.load(f)

    critical_vars = {}
    if os.path.exists(args.critical):
        with open(args.critical, "r") as f:
            critical_vars = json.load(f)

    generalizer = OperationGeneralizer(events, critical_vars)
    result = generalizer.generalize()

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(result, f, indent=4)

    print(f"\n[OK] Generalized actions saved to {args.output}")
    print(f"     Total operations: {result['summary']['total_operations']}")
    print(f"     Symbolic objects: {list(result['summary']['symbolic_objects'].keys())}")
    for sym, info in result['summary']['symbolic_objects'].items():
        print(f"       {sym}: chunk at {info['chunk_addr']}")
