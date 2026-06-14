from typing import Dict, List, Set, Optional, Tuple
from core.state.heap_state import AbstractHeapState
from core.capabilities.models import Capability, CapabilityDemand
from core.graph.edges import TechniqueEdge, TechniqueFootprint
from core.graph.seed_edges import get_seed_edges
from core.capabilities.deriver import CapabilityDeriver


class CapabilityGraph:
    def __init__(self):
        self.edges: List[TechniqueEdge] = []
        self._edge_index: Dict[str, List[int]] = {}
        self._seed()

    def _seed(self):
        for edge in get_seed_edges():
            self.add_edge(edge)

    def add_edge(self, edge: TechniqueEdge):
        idx = len(self.edges)
        self.edges.append(edge)
        for cap_name in edge.produces():
            if cap_name not in self._edge_index:
                self._edge_index[cap_name] = []
            self._edge_index[cap_name].append(idx)

    def find_path(self,
                  state: AbstractHeapState,
                  bugs: Set[str],
                  caps: List[Capability],
                  target_demand: CapabilityDemand,
                  max_depth: int = 5,
                  slot: int = -1) -> Optional[List[TechniqueEdge]]:
        if slot < 0:
            for s, ch in state.slots.items():
                if ch.status in ("freed", "allocated", "empty"):
                    slot = s
                    break
            if slot < 0:
                slot = 0

        best_path = None
        best_cost = float("inf")

        def dfs(current_caps: List[Capability],
                current_bugs: Set[str],
                depth: int,
                path: List[TechniqueEdge],
                used_footprints: List[TechniqueFootprint]):

            nonlocal best_path, best_cost

            if any(c.satisfies(target_demand) for c in current_caps):
                if sum(e.cost for e in path) < best_cost:
                    best_path = list(path)
                    best_cost = sum(e.cost for e in path)
                return

            if depth >= max_depth:
                return

            for idx, edge in enumerate(self.edges):
                if any(edge.technique_id == e.technique_id for e in path):
                    continue
                if not edge.applicable(state, current_bugs, current_caps, slot):
                    continue
                fp_conflict = any(
                    edge.footprint.conflicts_with(fp)
                    for fp in used_footprints
                )
                if fp_conflict:
                    continue
                new_caps = current_caps + edge.post_caps
                new_path = path + [edge]
                new_fp = used_footprints + [edge.footprint]
                new_bugs = set(current_bugs)
                for c in edge.post_caps:
                    if c.name == "heap_leak":
                        new_bugs.add("heap_leak_possible")
                    elif c.name == "libc_leak":
                        new_bugs.add("libc_leak_possible")
                    elif c.name == "arbitrary_allocation":
                        new_bugs.add("potential_double_free")
                        new_bugs.add("potential_uaf")
                dfs(new_caps, new_bugs, depth + 1, new_path, new_fp)

        dfs(caps, bugs, 0, [], [])
        return best_path

    def find_path_to_goal(self,
                          state: AbstractHeapState,
                          bugs: Set[str],
                          goal: str,
                          slot: int = -1) -> Optional[List[TechniqueEdge]]:
        caps = CapabilityDeriver.derive(state)
        demand = CapabilityDemand(name=goal)
        return self.find_path(state, bugs, caps, demand, slot=slot)

    def edges_producing(self, cap_name: str) -> List[TechniqueEdge]:
        idxs = self._edge_index.get(cap_name, [])
        return [self.edges[i] for i in idxs]

    def get_all_techniques(self) -> List[str]:
        return list(set(e.technique_id for e in self.edges))
