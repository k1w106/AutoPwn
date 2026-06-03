from typing import List
from core.state.heap_state import AbstractHeapState
from core.capabilities.models import Capability, CapabilityDemand


class CapabilityDeriver:
    @staticmethod
    def derive(state: AbstractHeapState) -> List[Capability]:
        caps = []

        if "heap_leak_possible" in state.tags:
            caps.append(Capability(
                name="heap_leak",
                mode="single",
                max_bytes=8,
                address_space=["heap"],
                stability="stable",
                constraints=["require_uaf_view"],
                derived_from=("view", -1),
            ))

        if "libc_leak_possible" in state.tags:
            caps.append(Capability(
                name="libc_leak",
                mode="single",
                max_bytes=8,
                address_space=["libc"],
                stability="stable",
                constraints=["require_unsorted_bin_uaf"],
                derived_from=("view", -1),
            ))

        has_edit = any("uaf_edit_on" in tag for tag in state.tags)
        has_view = any("uaf_view_on" in tag for tag in state.tags)
        has_heap_leak = any(c.name == "heap_leak" for c in caps)
        has_uaf = has_edit or has_view

        if has_uaf and has_edit:
            caps.append(Capability(
                name="arbitrary_allocation",
                mode="bounded",
                max_bytes=8,
                address_space=["heap", "libc", "stack"],
                stability="fragile",
                constraints=["safe_linking_bypass", "tcache_not_full"],
                derived_from=("tcache_poisoning", -1),
            ))

        if "arbitrary_allocation_achieved" in state.tags:
            caps.append(Capability(
                name="arbitrary_allocation",
                mode="bounded",
                max_bytes=8,
                address_space=["heap", "libc", "stack"],
                stability="fragile",
            ))
            caps.append(Capability(
                name="arbitrary_read",
                mode="bounded",
                max_bytes=8,
                address_space=["heap", "libc", "stack"],
                stability="fragile",
                constraints=["require_alloc_then_view"],
            ))
            caps.append(Capability(
                name="arbitrary_write",
                mode="bounded",
                max_bytes=8,
                address_space=["heap", "libc", "stack"],
                stability="fragile",
                constraints=["require_alloc_then_edit"],
            ))

        for slot, chunk in state.slots.items():
            if chunk.status == "allocated" and chunk.has_libc_ptr:
                if not any(c.name == "libc_leak" for c in caps):
                    caps.append(Capability(
                        name="libc_leak",
                        mode="single",
                        max_bytes=8,
                        address_space=["libc"],
                        stability="stable",
                        derived_from=("view", slot),
                    ))

        return caps

    @staticmethod
    def derive_abstract(state: AbstractHeapState) -> List[Capability]:
        return CapabilityDeriver.derive(state)

    @staticmethod
    def check_demand(state: AbstractHeapState, demand: CapabilityDemand) -> bool:
        caps = CapabilityDeriver.derive(state)
        return any(c.satisfies(demand) for c in caps)
