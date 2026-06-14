import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from pwn import ELF


@dataclass
class AllocatorPolicy:
    glibc_major: int
    glibc_minor: int

    @property
    def tcache_enabled(self) -> bool:
        return (self.glibc_major, self.glibc_minor) >= (2, 26)

    @property
    def safe_linking(self) -> bool:
        return (self.glibc_major, self.glibc_minor) >= (2, 32)

    @property
    def has_hooks(self) -> bool:
        return (self.glibc_major, self.glibc_minor) < (2, 34)

    @property
    def tcache_max_per_size(self) -> int:
        return 7

    @property
    def tcache_max_size(self) -> int:
        return 0x410

    @property
    def fastbin_max_size(self) -> int:
        return 0x80

    def resolve_free_branches(self, size_class: int,
                              tcache_count: int,
                              has_adjacent_free: bool) -> List[str]:
        branches = []
        if self.tcache_enabled and tcache_count < self.tcache_max_per_size:
            branches.append("tcache")
        if size_class <= self.fastbin_max_size:
            if "tcache" not in branches:
                branches.append("fastbin")
        if has_adjacent_free:
            branches.append("consolidation")
        if not branches:
            branches.append("unsorted_bin")
        return branches


@dataclass
class Environment:
    glibc_version: str = "2.39"
    alloc_policy: AllocatorPolicy = field(default_factory=lambda: AllocatorPolicy(2, 39))

    relro: str = "Full"
    pie: bool = False
    nx: bool = True
    canary: bool = False
    cet: bool = False

    available_ops: Set[str] = field(default_factory=lambda: {"alloc", "free", "view", "edit"})
    max_slots: int = 10
    menu_prompt: str = "b'> '"
    index_base: int = 0

    binary_path: str = ""
    libc_path: Optional[str] = None
    ld_path: Optional[str] = None
    interface_map: dict = field(default_factory=dict)

    # Probed heap layout (set by ChunkProber)
    chunk_size: int = 0x40
    heap_base: int = 0  # probed heap base
    c0_addr: int = 0
    c1_addr: int = 0
    c2_addr: int = 0

    @property
    def glibc_major(self) -> int:
        return self.alloc_policy.glibc_major

    @property
    def glibc_minor(self) -> int:
        return self.alloc_policy.glibc_minor

    @property
    def safe_linking(self) -> bool:
        return self.alloc_policy.safe_linking

    @property
    def has_hooks(self) -> bool:
        return self.alloc_policy.has_hooks

    @staticmethod
    def _detect_glibc_version(libc_path: str) -> str:
        if not libc_path or not os.path.exists(libc_path):
            return "2.39"
        try:
            with open(libc_path, 'rb') as f:
                raw = f.read()
            for m in re.finditer(rb'GNU C Library[^)]*\)[^0-9]*([0-9]+\.[0-9]+)', raw):
                return m.group(1).decode()
        except Exception:
            pass
        fallback = ELF(libc_path, checksec=False)
        fh = fallback.symbols.get('__free_hook', None)
        mh = fallback.symbols.get('__malloc_hook', None)
        has_hooks = (fh is not None and fh != 0) or (mh is not None and mh != 0)
        has_tcache = any('tcache' in s.lower() for s in fallback.symbols)
        if has_hooks:
            return "2.29" if has_tcache else "2.23"
        return "2.39"

    @staticmethod
    def _scan_main_arena(libc_elf) -> Optional[int]:
        malloc_addr = libc_elf.symbols.get('__libc_malloc', 0)
        if not malloc_addr:
            return None
        try:
            data = libc_elf.read(malloc_addr, 0x600)
        except Exception:
            return None
        for i in range(len(data) - 7):
            if data[i:i+3] == b'\x48\x8d\x1d':
                off = int.from_bytes(data[i+3:i+7], 'little', signed=True)
                target = malloc_addr + i + 7 + off
                if 0x100000 < target < 0x400000:
                    return target
        return None

    @classmethod
    def build(cls, binary_path: str,
              libc_path: Optional[str] = None,
              ld_path: Optional[str] = None,
              interface_map: Optional[dict] = None) -> "Environment":
        env = cls()
        env.binary_path = binary_path
        env.libc_path = libc_path
        env.ld_path = ld_path

        ver = cls._detect_glibc_version(libc_path or binary_path)
        env.glibc_version = ver
        parts = ver.split(".")
        env.alloc_policy = AllocatorPolicy(
            glibc_major=int(parts[0]),
            glibc_minor=int(parts[1]) if len(parts) > 1 else 0,
        )

        if os.path.exists(binary_path):
            try:
                elf = ELF(binary_path, checksec=False)
                cs = elf.checksec()
                if isinstance(cs, dict):
                    env.relro = cs.get('relro', 'Full')
                    env.pie = cs.get('pie', False)
                    env.nx = cs.get('nx', True)
                    env.canary = cs.get('canary', False)
                    env.cet = cs.get('cet', False)
            except Exception:
                pass

        if interface_map:
            env.interface_map = interface_map
            ops = interface_map.get("operations", {})
            found_ops = set()
            for ch, info in ops.items():
                role = info.get("role")
                if role in ("alloc", "free", "view", "edit"):
                    found_ops.add(role)
            if found_ops:
                env.available_ops = found_ops
            env.menu_prompt = interface_map.get("menu_prompt", "b'> '")
            env.max_slots = cls._detect_max_slots(interface_map)

        return env

    @staticmethod
    def _detect_max_slots(interface_map: dict) -> int:
        ops = interface_map.get("operations", {})
        for ch, info in ops.items():
            if info.get("role") == "alloc":
                for step in info.get("steps", []):
                    if step.get("arg") == "idx":
                        prompt = str(step.get("prompt", "")).lower()
                        m = re.search(r'0-(\d+)', prompt)
                        if m:
                            return int(m.group(1)) + 1
        return 20
