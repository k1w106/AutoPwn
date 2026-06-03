from core.state.heap_state import AbstractHeapState


class HeapInvariant:
    @staticmethod
    def tcache_count_consistency(state: AbstractHeapState) -> bool:
        for size_class, count in state.tcache_counts.items():
            regions = state.tcache_bins.get(size_class, set())
            actual = sum(1 for rid in regions
                        if rid in state.regions and state.regions[rid].status == "freed")
            if count != actual:
                return False
        return True

    @staticmethod
    def tcache_max_per_size(state: AbstractHeapState) -> bool:
        return all(c <= 7 for c in state.tcache_counts.values())

    @staticmethod
    def no_dangling_region_refs(state: AbstractHeapState) -> bool:
        for slot, rid in state.slot_to_region.items():
            if rid not in state.regions:
                return False
        return True

    @staticmethod
    def unsorted_bin_invariants(state: AbstractHeapState) -> bool:
        for rid in state.unsorted_bin_regions:
            region = state.regions.get(rid)
            if region and region.current_chunk:
                if region.current_chunk.size_class <= 0x410:
                    return False
        return True

    @staticmethod
    def slot_region_consistency(state: AbstractHeapState) -> bool:
        for slot, rid in state.slot_to_region.items():
            region = state.regions.get(rid)
            if region and slot not in region.aliased_by:
                return False
        return True

    @classmethod
    def check_all(cls, state: AbstractHeapState) -> bool:
        checks = [
            cls.tcache_count_consistency,
            cls.tcache_max_per_size,
            cls.no_dangling_region_refs,
            cls.unsorted_bin_invariants,
            cls.slot_region_consistency,
        ]
        for check in checks:
            if not check(state):
                return False
        return True
