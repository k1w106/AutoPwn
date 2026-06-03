from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
from core.state.heap_state import AbstractHeapState


@dataclass
class DetectedBug:
    name: str
    evidence: str = ""
    confidence: float = 1.0


@dataclass
class DetectedBugs:
    bugs: Dict[str, DetectedBug] = field(default_factory=dict)

    def add(self, name: str, evidence: str = "", confidence: float = 1.0):
        if name not in self.bugs or confidence > self.bugs[name].confidence:
            self.bugs[name] = DetectedBug(name=name, evidence=evidence, confidence=confidence)

    def has(self, name: str) -> bool:
        return name in self.bugs

    def names(self) -> Set[str]:
        return set(self.bugs.keys())

    def __contains__(self, name: str) -> bool:
        return name in self.bugs


class BugDetector:
    @staticmethod
    def from_trace(trace_events: List[dict]) -> DetectedBugs:
        bugs = DetectedBugs()
        freed_set = {}
        seen_frees = {}

        for ev in trace_events:
            etype = ev.get("type", "")
            addr = ev.get("addr", "0x0")
            slot = ev.get("slot", -1)
            note = ev.get("note", "").lower()

            if etype == "Free":
                if addr in freed_set and freed_set[addr]:
                    bugs.add("double_free",
                             evidence=f"Free of {addr} twice",
                             confidence=0.9)
                freed_set[addr] = True
                if slot >= 0:
                    seen_frees[slot] = seen_frees.get(slot, 0) + 1
                    if seen_frees[slot] > 1:
                        bugs.add("double_free",
                                 evidence=f"Slot {slot} freed {seen_frees[slot]} times",
                                 confidence=0.8)

            if etype in ("Read", "Write") and addr in freed_set:
                bugs.add("uaf",
                         evidence=f"{etype} on freed {addr}",
                         confidence=0.7)

            if etype == "Read" and "libc" in note:
                bugs.add("libc_leak_possible",
                         evidence=f"Read with libc hint: {note}")

            if "heap" in note and "leak" in note:
                bugs.add("heap_leak_possible",
                         evidence=f"Note contains heap leak hint: {note}")

        return bugs

    @staticmethod
    def from_interface(interface_map: dict) -> DetectedBugs:
        bugs = DetectedBugs()
        if not interface_map:
            return bugs

        ops = interface_map.get("operations", {})
        roles = {}
        for ch, info in ops.items():
            role = info.get("role")
            if role:
                roles[role] = ch

        if "view" in roles and "free" in roles:
            free_steps = ops.get(roles["free"], {}).get("steps", [])
            view_steps = ops.get(roles["view"], {}).get("steps", [])
            free_has_idx = any(s.get("arg") == "idx" for s in free_steps)
            view_has_idx = any(s.get("arg") == "idx" for s in view_steps)
            if free_has_idx and view_has_idx:
                bugs.add("potential_uaf",
                         evidence="free + view with idx → UAF possible",
                         confidence=0.5)

        if "free" in roles and "alloc" in roles:
            alloc_steps = ops.get(roles["alloc"], {}).get("steps", [])
            free_steps = ops.get(roles["free"], {}).get("steps", [])
            alloc_has_idx = any(s.get("arg") == "idx" for s in alloc_steps)
            free_has_idx = any(s.get("arg") == "idx" for s in free_steps)
            if free_has_idx and alloc_has_idx:
                bugs.add("potential_double_free",
                         evidence="free + alloc with idx → double free possible",
                         confidence=0.4)

        return bugs

    @staticmethod
    def merge(into: DetectedBugs, other: DetectedBugs) -> DetectedBugs:
        merged = DetectedBugs()
        merged.bugs = dict(into.bugs)
        for name, bug in other.bugs.items():
            if name not in merged.bugs or bug.confidence > merged.bugs[name].confidence:
                merged.bugs[name] = bug
        return merged

    @classmethod
    def detect(cls, trace_events: List[dict],
               interface_map: dict) -> DetectedBugs:
        from_trace = cls.from_trace(trace_events)
        from_iface = cls.from_interface(interface_map)
        return cls.merge(from_trace, from_iface)
