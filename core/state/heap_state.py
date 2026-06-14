from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any


@dataclass
class AbstractChunk:
    size_class: int = 0x30
    status: str = "empty"
    has_libc_ptr: bool = False
    has_heap_ptr: bool = False
    fd: Optional[int] = None
    bk: Optional[int] = None
    tagged: Set[str] = field(default_factory=set)

    def clone(self) -> "AbstractChunk":
        return AbstractChunk(
            size_class=self.size_class,
            status=self.status,
            has_libc_ptr=self.has_libc_ptr,
            has_heap_ptr=self.has_heap_ptr,
            fd=self.fd,
            bk=self.bk,
            tagged=set(self.tagged),
        )


@dataclass
class MemoryRegion:
    region_id: str
    aliased_by: Set[int] = field(default_factory=set)
    status: str = "live"
    current_chunk: Optional[AbstractChunk] = None
    freed_count: int = 0

    def clone(self) -> "MemoryRegion":
        return MemoryRegion(
            region_id=self.region_id,
            aliased_by=set(self.aliased_by),
            status=self.status,
            current_chunk=self.current_chunk.clone() if self.current_chunk else None,
            freed_count=self.freed_count,
        )


@dataclass
class ExecutionTrace:
    ops: List[Tuple[str, int, str]] = field(default_factory=list)
    free_sequence: List[Tuple[int, int]] = field(default_factory=list)
    alloc_after_free: Dict[int, int] = field(default_factory=dict)

    def record_op(self, op_type: str, slot: int, detail: str = ""):
        self.ops.append((op_type, slot, detail))

    def record_free(self, slot: int, size_class: int):
        self.free_sequence.append((slot, size_class))

    def record_alloc(self, slot: int):
        for fs, _ in list(self.free_sequence):
            if fs == slot:
                self.alloc_after_free[slot] = self.alloc_after_free.get(slot, 0) + 1
                break

    def is_double_free_possible(self, slot: int) -> bool:
        count = sum(1 for fs, _ in self.free_sequence if fs == slot)
        alloc_count = self.alloc_after_free.get(slot, 0)
        return count - alloc_count == 1

    def has_freed_since_last_alloc(self, slot: int) -> bool:
        return self.is_double_free_possible(slot)

    def clone(self) -> "ExecutionTrace":
        return ExecutionTrace(
            ops=list(self.ops),
            free_sequence=list(self.free_sequence),
            alloc_after_free=dict(self.alloc_after_free),
        )


@dataclass
class AbstractHeapState:
    slots: Dict[int, AbstractChunk] = field(default_factory=dict)
    regions: Dict[str, MemoryRegion] = field(default_factory=dict)
    slot_to_region: Dict[int, str] = field(default_factory=dict)
    tcache_counts: Dict[int, int] = field(default_factory=dict)
    tcache_bins: Dict[int, Set[str]] = field(default_factory=dict)
    unsorted_bin_regions: Set[str] = field(default_factory=set)
    tags: Set[str] = field(default_factory=set)
    trace: ExecutionTrace = field(default_factory=ExecutionTrace)
    heap_base_sym: Optional[str] = None
    libc_base_sym: Optional[str] = None
    next_region_id: int = 0

    def clone(self) -> "AbstractHeapState":
        new = AbstractHeapState()
        new.slots = {k: v.clone() for k, v in self.slots.items()}
        new.regions = {k: v.clone() for k, v in self.regions.items()}
        new.slot_to_region = dict(self.slot_to_region)
        new.tcache_counts = dict(self.tcache_counts)
        new.tcache_bins = {k: set(v) for k, v in self.tcache_bins.items()}
        new.unsorted_bin_regions = set(self.unsorted_bin_regions)
        new.tags = set(self.tags)
        new.trace = self.trace.clone()
        new.heap_base_sym = self.heap_base_sym
        new.libc_base_sym = self.libc_base_sym
        new.next_region_id = self.next_region_id
        return new

    def _new_region_id(self) -> str:
        rid = f"R{self.next_region_id}"
        self.next_region_id += 1
        return rid

    def get_or_create_slot(self, slot: int, size_class: int = 0x30) -> int:
        if slot not in self.slots:
            self.slots[slot] = AbstractChunk(size_class=size_class)
        if slot not in self.slot_to_region:
            rid = self._new_region_id()
            self.slot_to_region[slot] = rid
            self.regions[rid] = MemoryRegion(
                region_id=rid,
                aliased_by={slot},
                current_chunk=self.slots[slot],
            )
        return slot

    def allocate_at_slot(self, slot: int, size_class: int) -> "AbstractHeapState":
        s = self.clone()
        s.get_or_create_slot(slot, size_class)
        rid = s.slot_to_region[slot]
        s.regions[rid].status = "live"
        s.regions[rid].current_chunk = s.slots[slot]
        s.slots[slot].status = "allocated"
        s.slots[slot].size_class = size_class
        s.trace.record_alloc(slot)
        return s

    def free_slot(self, slot: int) -> "AbstractHeapState":
        s = self.clone()
        if slot not in s.slots:
            return s
        size_class = s.slots[slot].size_class
        rid = s.slot_to_region[slot]
        region = s.regions[rid]
        region.status = "freed"
        region.freed_count += 1
        s.slots[slot].status = "freed"
        s.tcache_counts[size_class] = s.tcache_counts.get(size_class, 0) + 1
        if size_class not in s.tcache_bins:
            s.tcache_bins[size_class] = set()
        s.tcache_bins[size_class].add(rid)
        s.trace.record_free(slot, size_class)
        if region.freed_count > 1:
            s.tags.add(f"double_free_on_slot_{slot}")
        return s

    def view_slot(self, slot: int) -> "AbstractHeapState":
        s = self.clone()
        if slot in s.slots and s.slots[slot].status == "freed":
            chunk = s.slots[slot]
            if chunk.has_libc_ptr:
                s.tags.add("libc_leak_possible")
            if chunk.has_heap_ptr or chunk.size_class <= 0x410:
                s.tags.add("heap_leak_possible")
            s.tags.add(f"uaf_view_on_{slot}")
        return s

    def edit_slot(self, slot: int) -> "AbstractHeapState":
        s = self.clone()
        if slot in s.slots and s.slots[slot].status == "freed":
            s.tags.add(f"uaf_edit_on_{slot}")
        return s

    def alloc_at_target(self, slot: int, size_class: int) -> "AbstractHeapState":
        s = self.clone()
        s.tcache_counts[size_class] = max(0, s.tcache_counts.get(size_class, 1) - 1)
        s.tags.add("arbitrary_allocation_achieved")
        return s

    @staticmethod
    def build_empty(max_slots: int = 10) -> "AbstractHeapState":
        s = AbstractHeapState()
        for i in range(min(max_slots, 64)):
            slot = i
            s.slots[slot] = AbstractChunk(status="empty")
            rid = f"R{i}"
            s.slot_to_region[slot] = rid
            s.regions[rid] = MemoryRegion(region_id=rid, aliased_by={slot})
        s.next_region_id = max_slots
        return s

    def summary(self) -> str:
        lines = [f"HeapState: {len(self.slots)} slots, {len(self.regions)} regions"]
        for slot, chunk in self.slots.items():
            status = chunk.status
            tags = ",".join(sorted(chunk.tagged)) if chunk.tagged else ""
            lines.append(f"  slot {slot}: {status} ({hex(chunk.size_class)}) [{tags}]")
        lines.append(f"  tcache: {dict(self.tcache_counts)}")
        lines.append(f"  tags: {sorted(self.tags)}")
        return "\n".join(lines)

    def abstract_signature(self) -> Tuple:
        tcache = frozenset(self.tcache_counts.items())
        slot_statuses = tuple(
            (slot, ch.status, frozenset(ch.tagged))
            for slot, ch in sorted(self.slots.items())
            if ch.status != "empty"
        )
        alias_structure = frozenset(
            (len(r.aliased_by), r.status)
            for r in self.regions.values()
        )
        tags = frozenset(self.tags)
        last_frees = tuple(self.trace.free_sequence[-3:])
        return (tcache, slot_statuses, alias_structure, tags, last_frees)
