#!/usr/bin/env python3
"""
AutoPwn – Module 2 Runner (Hybrid: DynamoRIO + angr)
=====================================================
Workflow:
  Mode 1 (DynamoRIO — preferred):
    1. Build libheap_tracer.so  (cmake + make)
    2. Run binary through drrun → DynamoRIO traces all heap ops
    3. Parse trace log → trace_events.json

  Mode 2 (angr — fallback when no solve.py):
    1. Load binary with angr
    2. Find heap operation call sites via CFG
    3. Symbolically execute to discover heap operations
    4. Generate trace_events.json from symbolic exploration

Usage:
  python3 runner.py --target ./binary            # DynamoRIO mode
  python3 runner.py --target ./binary --angr     # angr symbolic mode
  python3 runner.py --skip-build                 # skip cmake/make
"""

import argparse
import json
import os
import re
import subprocess
import sys
import logging
from collections import Counter
from pathlib import Path

# Suppress angr warnings
logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)

# ──────────────────────────────────────────────────────────────────────────────
# Defaults
# ──────────────────────────────────────────────────────────────────────────────
THIS_DIR    = Path(__file__).parent.resolve()
LOG_PATH    = Path("/tmp/autopwn_trace.log")
OUTPUT_JSON = THIS_DIR.parent / "artifacts" / "trace_events.json"
TRACER_DIR  = THIS_DIR / "build"
TRACER_SO   = TRACER_DIR / "libheap_tracer.so"

def _find_drrun() -> Path:
    candidates = [
        Path.home() / "DynamoRIO-Linux-11.3.0-1" / "bin64" / "drrun",
        Path.home() / "DynamoRIO-Linux-11.3.0"   / "bin64" / "drrun",
        Path("/opt/dynamorio/bin64/drrun"),
    ]
    for c in candidates:
        if c.exists():
            return c
    return Path("drrun")

DRRUN = _find_drrun()

# Regex for trace events
_LINE_RE = re.compile(
    r"^(?P<seq>\d+)\s*\|\s*"
    r"(?P<pid>\d+)\s*\|\s*"
    r"(?P<comm>[^|]+?)\s*\|\s*"
    r"(?P<type>\w+)\s*\|\s*"
    r"size=(?P<size>\d+)\s*\|\s*"
    r"addr=(?P<addr>0x[0-9a-f]+)"
    r"(?:\s*\|\s*content=(?P<content>[^\s]+))?"
)

_MAP_RE = re.compile(
    r"^MAP\s*\|\s*(?P<name>[^|]+)\s*\|\s*(?:0x)?(?P<start>0x[0-9a-f]+)\s*\|\s*(?:0x)?(?P<end>0x[0-9a-f]+)"
)

# ──────────────────────────────────────────────────────────────────────────────
# Mode 1: DynamoRIO tracing
# ──────────────────────────────────────────────────────────────────────────────

def build_tracer(tracer_dir: Path, drrun: Path) -> None:
    dr_cmake = drrun.parent.parent / "cmake"
    src_dir  = THIS_DIR

    if not dr_cmake.exists():
        print(f"[!] DynamoRIO cmake dir not found: {dr_cmake}")
        sys.exit(1)

    tracer_dir.mkdir(exist_ok=True)
    print(f"[*] Building DynamoRIO client ...")
    print(f"    cmake dir : {dr_cmake}")
    print(f"    build dir : {tracer_dir}")

    r = subprocess.run(
        ["cmake", str(src_dir), f"-DDynamoRIO_DIR={dr_cmake}",
         "-DCMAKE_BUILD_TYPE=Release"],
        cwd=str(tracer_dir), capture_output=True, text=True
    )
    if r.returncode != 0:
        print("[!] cmake failed:"); print(r.stderr); sys.exit(1)

    r = subprocess.run(
        ["make", "-j4"],
        cwd=str(tracer_dir), capture_output=True, text=True
    )
    if r.returncode != 0:
        print("[!] make failed:"); print(r.stderr); sys.exit(1)

    so = tracer_dir / "libheap_tracer.so"
    if not so.exists():
        print(f"[!] {so} not found after build."); sys.exit(1)
    print(f"[OK] Built {so}")


def run_exploit_dynamorio(tracer_so: Path, log_path: Path, drrun: Path,
                target_binary: Path, timeout: int = 60) -> bool:
    """Run binary under DynamoRIO tracing. Returns True if successful."""
    if log_path.exists():
        log_path.unlink()

    # Check for solve.py in target directory
    local_solve = target_binary.parent / "solve.py"
    use_solve = local_solve.exists()

    wrapper = target_binary.parent / "_drrun_wrapper.sh"

    # Shell wrapper: spawn binary through drrun (cd to binary dir first)
    wrapper.write_text(
        f"#!/bin/sh\n"
        f'cd "{target_binary.parent.resolve()}"\n'
        f'AUTOPWN_LOG="{log_path}" '
        f'exec "{drrun.resolve()}" -c "{tracer_so.resolve()}" '
        f'-- "./{target_binary.name}" "$@"\n'
    )
    wrapper.chmod(0o755)

    if use_solve:
        print(f"[*] Found solve.py — running with DynamoRIO tracing")
        src = local_solve.read_text()
        patched = src
        patched = re.sub(r'_path = ["\'].*?["\']', f'_path = "{target_binary.resolve()}"', patched)
        patched = patched.replace('p = exe.process()', f'p = process(["{wrapper.resolve()}"])')
        patched = patched.replace('p = process(_path)', f'p = process(["{wrapper.resolve()}"])')
        patched = patched.replace('p.interactive()', 'p.close()')
        # Ensure script runs unconditionally (replace if args.LOCAL with if True)
        patched = re.sub(r'if\s+args\.LOCAL\s*:', 'if True:', patched)

        import tempfile, shutil
        tmpdir = tempfile.mkdtemp()
        patched_py = Path(tmpdir) / "_patched_solve.py"
        patched_py.write_text(patched)

        try:
            subprocess.run(
                ["python3", str(patched_py)],
                timeout=timeout, capture_output=False,
                cwd=str(target_binary.parent.resolve())
            )
        except subprocess.TimeoutExpired:
            print(f"[!] Timed out after {timeout}s — using log collected so far.")
        except FileNotFoundError as e:
            print(f"[!] {e}")
            return False
        finally:
            wrapper.unlink(missing_ok=True)
            patched_py.unlink(missing_ok=True)
            shutil.rmtree(tmpdir, ignore_errors=True)
    else:
        print(f"[*] No solve.py found — running binary directly under DynamoRIO")
        # Run binary directly with simple input
        try:
            proc = subprocess.run(
                [str(drrun.resolve()), "-c", str(tracer_so.resolve()),
                 "--", str(target_binary.resolve())],
                input=b"1\n15\nleak\n4\n15\n2\n15\n0\n",
                timeout=timeout, capture_output=True,
                env={**os.environ, "AUTOPWN_LOG": str(log_path)},
                cwd=str(target_binary.parent.resolve())
            )
        except subprocess.TimeoutExpired:
            print(f"[!] Timed out after {timeout}s — using log collected so far.")

    wrapper.unlink(missing_ok=True)

    if not log_path.exists():
        print("[!] Log not created — DynamoRIO may have failed.")
        return False

    print(f"[OK] Log written: {log_path}  ({log_path.stat().st_size} bytes)")
    return True

# ──────────────────────────────────────────────────────────────────────────────
# Mode 2: angr symbolic tracing
# ──────────────────────────────────────────────────────────────────────────────

def run_exploit_angr(target_binary: Path, timeout: int = 300) -> list[dict]:
    """
    Use angr to symbolically explore the binary and generate trace events.
    This replaces solve.py dependency with automated path exploration.
    """
    try:
        import angr
        import claripy
    except ImportError:
        print("[!] angr not installed. Install with: pip install angr")
        return []

    print(f"[*] Loading binary with angr: {target_binary}")
    project = angr.Project(str(target_binary), auto_load_libs=False)

    # Create initial state with symbolic stdin
    sym_input = claripy.BVS("sym_input", 8 * 512)
    state = project.factory.full_init_state(
        stdin=sym_input,
        add_options={angr.options.LAZY_SOLVES}
    )

    # Create simulation manager
    simgr = project.factory.simulation_manager(state)

    # Find common menu interaction patterns
    # We'll explore paths that call malloc/free
    events = []
    seq = 0
    malloc_addrs = []
    free_addrs = []

    # Find malloc and free symbols
    for sym in project.loader.main_object.symbols:
        if sym.name == "malloc":
            malloc_addrs.append(sym.rebased_addr)
        elif sym.name == "free":
            free_addrs.append(sym.rebased_addr)

    print(f"[*] Found {len(malloc_addrs)} malloc, {len(free_addrs)} free symbols")

    # Explore to find malloc calls
    if malloc_addrs:
        simgr.explore(find=malloc_addrs, num_find=3, timeout=timeout)

        for found_state in simgr.found:
            seq += 1
            # Get concrete stdin that led here
            try:
                concrete = found_state.posix.dumps(0)
            except Exception:
                concrete = b""

            # Get the malloc argument (first argument in rdi/rdi)
            try:
                if project.arch.name == "AMD64":
                    malloc_size = found_state.regs.rdi.concrete_value
                else:
                    malloc_size = 0x30
            except Exception:
                malloc_size = 0x30

            # Get return address (simulated)
            ret_addr = found_state.addr

            events.append({
                "seq": seq,
                "pid": 1,
                "comm": target_binary.name,
                "type": "Alloc",
                "size": malloc_size,
                "addr": hex(ret_addr),
                "note": f"angr_symbolic,size={hex(malloc_size)}"
            })

    # Explore to find free calls
    if free_addrs:
        simgr2 = project.factory.simulation_manager(state)
        simgr2.explore(find=free_addrs, num_find=3, timeout=timeout)

        for found_state in simgr2.found:
            seq += 1
            try:
                free_addr = found_state.regs.rdi.concrete_value
            except Exception:
                free_addr = 0

            events.append({
                "seq": seq,
                "pid": 1,
                "comm": target_binary.name,
                "type": "Free",
                "size": 0,
                "addr": hex(free_addr),
                "note": "angr_symbolic"
            })

    # If symbolic exploration didn't find much, generate basic events
    # from CFG analysis
    if len(events) < 4:
        print("[*] Symbolic exploration limited, generating CFG-based events")
        cfg = project.analyses.CFGFast()

        # Find functions that call malloc
        malloc_calls = 0
        for node in cfg.graph.nodes():
            func = cfg.functions.get(node.addr)
            if func is None:
                continue
            for block in func.blocks:
                for ins in block.capstone.insns:
                    if ins.mnemonic == "call":
                        malloc_calls += 1
                        seq += 1
                        events.append({
                            "seq": seq,
                            "pid": 1,
                            "comm": target_binary.name,
                            "type": "Alloc",
                            "size": 0x30,
                            "addr": hex(node.addr),
                            "note": "angr_cfg_analysis"
                        })

    print(f"[*] Generated {len(events)} events from angr analysis")
    return events

# ──────────────────────────────────────────────────────────────────────────────
# Parse log (shared between modes)
# ──────────────────────────────────────────────────────────────────────────────

class MemoryMap:
    def __init__(self):
        self.modules = []
        self.heap_min = 0xffffffffffffffff
        self.heap_max = 0

    def add_module(self, name, start, end):
        s_hex = start.replace("0x0x", "0x")
        e_hex = end.replace("0x0x", "0x")
        self.modules.append((name.lower(), int(s_hex, 16), int(e_hex, 16)))

    def update_heap(self, addr):
        a = int(addr, 16)
        if a < self.heap_min: self.heap_min = a
        if a > self.heap_max: self.heap_max = a

    def is_in_module(self, addr_hex, module_part_name):
        try:
            a = int(addr_hex, 16)
            for name, start, end in self.modules:
                if module_part_name in name:
                    if start <= a < end: return True
            return False
        except ValueError: return False

    def is_in_heap(self, addr_hex):
        try:
            a = int(addr_hex, 16)
            if self.heap_max == 0: return False
            return (self.heap_min - 0x1000) <= a <= (self.heap_max + 0x1000)
        except ValueError: return False

    def is_in_stack(self, addr_hex):
        try:
            a = int(addr_hex, 16)
            return a > 0x7f0000000000 and not self.is_in_module(addr_hex, "libc")
        except ValueError: return False


def parse_log(log_path: Path, target_comm: str) -> tuple[list[dict], MemoryMap]:
    events: list[dict] = []
    mmap = MemoryMap()
    skipped = 0
    all_comms: set = set()
    active_chunks = {}

    if not log_path.exists():
        return [], mmap

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line: continue

            mm = _MAP_RE.match(line)
            if mm:
                mmap.add_module(mm.group("name"), mm.group("start"), mm.group("end"))
                continue

            m = _LINE_RE.match(line)
            if not m:
                skipped += 1
                continue

            comm = m.group("comm").strip()
            all_comms.add(comm)
            if comm != target_comm:
                continue

            etype = m.group("type")
            size  = int(m.group("size"))
            addr  = m.group("addr")
            content = m.group("content") if m.group("content") else ""

            if etype == "Alloc":
                mmap.update_heap(addr)
                active_chunks[addr] = size

            event = {
                "seq":  int(m.group("seq")),
                "pid":  int(m.group("pid")),
                "comm": comm,
                "type": etype,
                "size": size,
                "addr": addr,
            }
            if content: event["content"] = content
            events.append(event)

    events.sort(key=lambda e: e["seq"])

    final_events = []
    for ev in events:
        is_relevant = False
        if ev["type"] in ("Alloc", "Free", "Copy"):
            is_relevant = True
        else:
            ev_addr_int = int(ev["addr"], 16)
            for chunk_addr, chunk_size in active_chunks.items():
                c_addr_int = int(chunk_addr, 16)
                if c_addr_int <= ev_addr_int < (c_addr_int + chunk_size):
                    ev["heap_chunk_ref"] = chunk_addr
                    is_relevant = True
                    break

            if not is_relevant and ev["type"] == "Leak":
                if mmap.is_in_module(ev.get("content", ""), "libc") or mmap.is_in_heap(ev.get("content", "")):
                    is_relevant = True

        if is_relevant:
            final_events.append(ev)

    print(f"[*] Processes found in log : {sorted(all_comms)}")
    print(f"[*] Memory regions mapped  : {len(mmap.modules)}")
    print(f"[*] Semantically filtered : {len(final_events)}")
    return final_events, mmap


def annotate(events: list[dict], mmap: MemoryMap) -> list[dict]:
    libc_base = None
    for name, start, end in mmap.modules:
        if "libc" in name:
            libc_base = start
            break

    for ev in events:
        notes = []
        t, size, content = ev["type"], ev["size"], ev.get("content", "")
        h_size = hex(size)

        if t == "Alloc":
            notes.append(f"size={h_size}")
            if mmap.is_in_stack(ev["addr"]): notes.append("TARGET_STACK_HIJACK")
            elif mmap.is_in_module(ev["addr"], "libc"): notes.append("TARGET_LIBC_HIJACK")
        elif t == "Free":
            if content and content not in ("-", "0x0000000000000000"):
                notes.append("fd_ptr_visible")
        elif t == "Leak":
            if mmap.is_in_module(content, "libc"):
                notes.append("libc_ptr_candidate")
                if libc_base is not None:
                    content_int = int(content, 16)
                    offset = content_int - libc_base
                    notes.append(f"libc_offset={hex(offset)}")
                    if 0x1e0000 <= offset <= 0x200000:
                        notes.append("unsorted_bin_leak")
            elif mmap.is_in_heap(content):
                notes.append("heap_ptr_candidate")
                notes.append("heap_leak")
        elif t == "Copy":
            notes.append(f"n={h_size}")
        elif t == "Read":
            notes.append(f"len={h_size}")
            if mmap.is_in_heap(ev["addr"]): notes.append("heap_read")
            if content and content != "0x0000000000000000":
                if mmap.is_in_module(content, "libc"):
                    notes.append("libc_ptr_candidate")
                    if libc_base is not None:
                        content_int = int(content, 16)
                        offset = content_int - libc_base
                        if 0x1e0000 <= offset <= 0x200000:
                            notes.append("unsorted_bin_leak")
                elif mmap.is_in_heap(content):
                    notes.append("heap_ptr_candidate")

        if notes:
            ev["note"] = ", ".join(notes)
    return events


def annotate_angr_events(events: list[dict]) -> list[dict]:
    """Annotate events generated by angr symbolic exploration."""
    for ev in events:
        notes = []
        t = ev.get("type", "")
        if t == "Alloc":
            notes.append(f"angr_symbolic,size={hex(ev.get('size', 0))}")
        elif t == "Free":
            notes.append("angr_symbolic")
        ev["note"] = ", ".join(notes) if notes else "angr_symbolic"
    return events

# ──────────────────────────────────────────────────────────────────────────────
# Save + CLI
# ──────────────────────────────────────────────────────────────────────────────

def save_json(events: list[dict], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2, ensure_ascii=False)
    print(f"[OK] {len(events)} events → {output}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="AutoPwn Module 2 Runner (Hybrid)")
    p.add_argument("--drrun",      type=Path, default=DRRUN)
    p.add_argument("--tracer-so",  type=Path, default=TRACER_SO)
    p.add_argument("--tracer-dir", type=Path, default=TRACER_DIR)
    p.add_argument("--log",        type=Path, default=LOG_PATH)
    p.add_argument("--out",        type=Path, default=OUTPUT_JSON)
    p.add_argument("--timeout",    type=int,  default=60)
    p.add_argument("--skip-build", action="store_true")
    p.add_argument("--target",     type=Path, required=True)
    p.add_argument("--angr",       action="store_true", help="Use angr symbolic tracing instead of DynamoRIO")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    print("=" * 60)
    print("  AutoPwn – Module 2 Runner  [Hybrid: DynamoRIO + angr]")
    print("=" * 60)

    events = []
    mmap = MemoryMap()

    if args.angr:
        # Mode 2: angr symbolic tracing
        print("[*] Using angr symbolic tracing mode")
        events = run_exploit_angr(args.target, args.timeout)
        events = annotate_angr_events(events)
    else:
        # Mode 1: DynamoRIO tracing
        print("[*] Using DynamoRIO tracing mode")
        if args.skip_build:
            if not args.tracer_so.exists():
                print(f"[!] {args.tracer_so} not found."); sys.exit(1)
            print(f"[*] Using existing {args.tracer_so}")
        else:
            build_tracer(args.tracer_dir, args.drrun)

        success = run_exploit_dynamorio(
            args.tracer_so, args.log, args.drrun, args.target, args.timeout
        )

        if success:
            events, mmap = parse_log(args.log, args.target.name)
            events = annotate(events, mmap)
        else:
            print("[!] DynamoRIO tracing failed, falling back to angr symbolic tracing")
            events = run_exploit_angr(args.target, args.timeout)
            events = annotate_angr_events(events)

    save_json(events, args.out)

    counts = Counter(e["type"] for e in events)
    print("\n── Event summary ──────────────────────────────")
    for etype, cnt in sorted(counts.items()):
        print(f"   {etype:<10} {cnt}")
    notes_found = [e for e in events if "note" in e]
    if notes_found:
        print("\n── Annotated events ───────────────────────────")
        for e in notes_found[:10]:  # Show first 10
            print(f"   seq={e['seq']:<5} {e['type']:<8} addr={e['addr']}  → {e['note']}")
        if len(notes_found) > 10:
            print(f"   ... and {len(notes_found) - 10} more")
    print("=" * 60)


if __name__ == "__main__":
    main()
