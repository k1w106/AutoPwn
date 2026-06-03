import os
from typing import List, Optional
from pwn import ELF
from core.analysis.environment import Environment
from core.capabilities.models import Capability, CapabilityDemand, ExploitTarget


class TargetDiscovery:
    @staticmethod
    def discover(binary_path: str, libc_path: Optional[str],
                 caps: List[Capability],
                 env: Environment,
                 mode: str = "primitives") -> List[ExploitTarget]:
        targets = []

        if mode == "full":
            # Code execution targets — only discover in full mode
            if env.alloc_policy.has_hooks:
                targets.append(ExploitTarget(
                    name="__free_hook",
                    address_expr="libc.symbols['__free_hook']",
                    required_demand=CapabilityDemand(
                        "arbitrary_write", mode="bounded", max_bytes=8,
                        address_space=["libc"],
                    ),
                    risk=0.1,
                    exploit_type="system",
                    requires_libc_leak=True,
                ))

            if env.relro == "Partial" and not env.pie:
                got_expr = "exe.got['free']" if os.path.exists(binary_path) else "libc.symbols['__free_hook']"
                targets.append(ExploitTarget(
                    name="got.free",
                    address_expr=got_expr,
                    required_demand=CapabilityDemand(
                        "arbitrary_write", mode="bounded", max_bytes=8,
                        address_space=["heap"],
                    ),
                    risk=0.2,
                    exploit_type="got_overwrite",
                    requires_libc_leak=True,
                ))

            targets.append(ExploitTarget(
                name="main_ret_addr",
                address_expr="stack_leak - 0x130",
                required_demand=CapabilityDemand(
                    "arbitrary_write", mode="bounded", max_bytes=8,
                    address_space=["stack"],
                ),
                risk=0.3,
                exploit_type="rop",
                requires_stack_leak=True,
                requires_libc_leak=True,
            ))

        if mode == "primitives":
            targets.append(ExploitTarget(
                name="primitives_only",
                address_expr="none",
                required_demand=CapabilityDemand("heap_leak"),
                risk=0.0,
                exploit_type="primitives",
            ))

        targets.sort(key=lambda t: t.risk)
        return targets
