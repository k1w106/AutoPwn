from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any


@dataclass
class CapabilityDemand:
    """A requirement for a capability with specific constraints."""
    name: str
    mode: str = "bounded"
    max_bytes: int = 8
    address_space: List[str] = field(default_factory=list)
    repeatable: bool = False
    stability: str = "fragile"

    def satisfied_by(self, cap: "Capability") -> bool:
        if cap.name != self.name:
            return False
        mode_ok = (self.mode == cap.mode or
                   (self.mode in ("bounded", "single") and
                    cap.mode in ("single", "bounded", "unbounded")) or
                   (self.mode == "unbounded"))
        if not mode_ok:
            return False
        if self.max_bytes > cap.max_bytes:
            return False
        if self.address_space:
            if not any(space in cap.address_space for space in self.address_space):
                return False
        return True


@dataclass
class Capability:
    name: str
    mode: str = "single"
    max_bytes: int = 8
    address_space: List[str] = field(default_factory=lambda: ["heap"])
    stability: str = "fragile"
    constraints: List[str] = field(default_factory=list)
    derived_from: Tuple[str, int] = ("", -1)

    def satisfies(self, demand: CapabilityDemand) -> bool:
        return demand.satisfied_by(self)

    def describe(self) -> str:
        return (f"{self.name}(mode={self.mode}, "
                f"bytes={self.max_bytes}, "
                f"spaces={self.address_space}, "
                f"stable={self.stability})")


@dataclass
class ExploitTarget:
    name: str
    address_expr: str
    required_demand: CapabilityDemand
    risk: float
    exploit_type: str
    security_requirements: Dict[str, Any] = field(default_factory=dict)
    requires_stack_leak: bool = False
    requires_libc_leak: bool = False

    def feasible_with(self, caps: List[Capability], env) -> bool:
        for key, val in self.security_requirements.items():
            if getattr(env, key, None) != val:
                return False
        if self.requires_stack_leak:
            if not any(c.name == "stack_leak" for c in caps):
                return False
        if self.requires_libc_leak:
            if not any(c.name == "libc_leak" for c in caps):
                return False
        return any(self.required_demand.satisfied_by(c) for c in caps)
