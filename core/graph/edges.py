from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from core.state.heap_state import AbstractHeapState, ExecutionTrace
from core.capabilities.models import Capability, CapabilityDemand


@dataclass
class TechniqueFootprint:
    mutates_slots: Set[int] = field(default_factory=set)
    consumes_tcache: Set[int] = field(default_factory=set)
    dirties_unsorted: bool = False
    leaves_fake_chunks: List[int] = field(default_factory=list)
    needs_free_slots: int = 0

    def conflicts_with(self, other: "TechniqueFootprint") -> bool:
        if self.consumes_tcache & other.consumes_tcache:
            return True
        if self.dirties_unsorted and other.dirties_unsorted:
            return True
        overlapping_fake = set(self.leaves_fake_chunks) & set(other.leaves_fake_chunks)
        if overlapping_fake:
            return True
        return False


@dataclass
class StatePattern:
    required_bugs: Set[str] = field(default_factory=set)
    required_ops: Set[str] = field(default_factory=set)
    required_caps: Set[str] = field(default_factory=set)
    required_tags: Set[str] = field(default_factory=set)

    def matches(self, state: AbstractHeapState,
                bugs: Set[str],
                caps: List[Capability]) -> bool:
        if self.required_bugs and not self.required_bugs.issubset(bugs):
            return False
        if self.required_caps:
            cap_names = {c.name for c in caps}
            if not self.required_caps.issubset(cap_names):
                return False
        if self.required_tags:
            if not self.required_tags.issubset(state.tags):
                return False
        return True


@dataclass
class HistoryCondition:
    last_op: Optional[str] = None
    no_alloc_between: bool = False
    freed_slot: Optional[int] = None
    min_free_on_slot: int = 1

    def matches(self, trace: ExecutionTrace, slot: int) -> bool:
        if self.last_op:
            if not trace.ops or trace.ops[-1][0] != self.last_op:
                return False
        if self.freed_slot is not None:
            frees = sum(1 for fs, _ in trace.free_sequence if fs == self.freed_slot)
            if frees < self.min_free_on_slot:
                return False
        if self.no_alloc_between:
            if trace.alloc_after_free.get(slot, 0) > 0:
                return False
        return True


@dataclass
class TechniqueEdge:
    technique_id: str
    pre_pattern: StatePattern
    history_condition: HistoryCondition
    post_caps: List[Capability]
    footprint: TechniqueFootprint
    cost: float = 1.0
    impl_steps: List[str] = field(default_factory=list)

    def applicable(self, state: AbstractHeapState,
                   bugs: Set[str],
                   caps: List[Capability],
                   slot: int) -> bool:
        if not self.pre_pattern.matches(state, bugs, caps):
            return False
        if not self.history_condition.matches(state.trace, slot):
            return False
        return True

    def produces(self) -> List[str]:
        return [c.name for c in self.post_caps]

    def describe(self) -> str:
        pre = ",".join(sorted(self.pre_pattern.required_bugs))
        post = ",".join(self.produces())
        return f"{self.technique_id}: [{pre}] → [{post}] (cost={self.cost})"
