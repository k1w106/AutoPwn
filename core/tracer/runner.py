#!/usr/bin/env python3
"""
AutoPwn – Module 2 Runner (DynamoRIO edition)
=============================================
Workflow:
  1. Build libheap_tracer.so  (cmake + make)
  2. Patch solve.py to spawn binary through drrun
  3. Run patched solve.py → DynamoRIO traces all heap ops
  4. Parse trace log → trace_events.json  (sent to Module 3)

Usage:
  python3 runner.py                        # default paths
  python3 runner.py --skip-build           # skip cmake/make
  python3 runner.py --drrun ~/DynamoRIO-Linux-11.3.0-1/bin64/drrun
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────────────
# Defaults
# ──────────────────────────────────────────────────────────────────────────────
THIS_DIR    = Path(__file__).parent.resolve()
SOLVE_PY    = THIS_DIR / "solve.py"
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

# Regex for MAP events: MAP | NAME | START | END
_MAP_RE = re.compile(
    r"^MAP\s*\|\s*(?P<name>[^|]+)\s*\|\s*(?:0x)?(?P<start>0x[0-9a-f]+)\s*\|\s*(?:0x)?(?P<end>0x[0-9a-f]+)"
)

# ──────────────────────────────────────────────────────────────────────────────
# Step 1 – Build DynamoRIO client
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

# ──────────────────────────────────────────────────────────────────────────────
# Step 2 – Run exploit under DynamoRIO
# ──────────────────────────────────────────────────────────────────────────────

def _find_binary(solve_py: Path) -> Path:
    for name in ("chall_patched", "chall"):
        b = solve_py.parent / name
        if b.exists():
            return b
    print("[!] Cannot find chall_patched or chall next to solve.py")
    sys.exit(1)


def run_exploit(tracer_so: Path, default_solve_py: Path,
                log_path: Path, drrun: Path,
                target_binary: Path,
                timeout: int = 60) -> None:
    if log_path.exists():
        log_path.unlink()
        print(f"[*] Removed old log: {log_path}")

    # Prioritize solve.py in the target binary's directory
    local_solve = target_binary.parent / "solve.py"
    solve_py = local_solve if local_solve.exists() else default_solve_py
    
    if solve_py == local_solve:
        print(f"[*] Found local solve script: {solve_py}")
    else:
        print(f"[*] Using default solve script: {solve_py}")

    wrapper = solve_py.parent / "_drrun_wrapper.sh"

    # Shell wrapper: pwntools execve("wrapper") → drrun → chall
    wrapper.write_text(
        f"#!/bin/sh\n"
        f'cd "{target_binary.parent.resolve()}"\n'
        f'AUTOPWN_LOG="{log_path}" '
        f'exec "{drrun.resolve()}" -c "{tracer_so.resolve()}" '
        f'-- "./{target_binary.name}" "$@"\n'
    )
    wrapper.chmod(0o755)

    # Patch solve.py
    src = solve_py.read_text()
    patched = src
    # Replace any local path with the target_binary path
    # We look for common patterns in solve.py
    patched = re.sub(r'_path = ["\'].*?["\']', f'_path = "{target_binary.resolve()}"', patched)

    patched = patched.replace('p = exe.process()', f'p = process(["{wrapper.resolve()}"])')
    patched = patched.replace('p = process(_path)', f'p = process(["{wrapper.resolve()}"])')
    patched = patched.replace('p.interactive()', 'p.sendline(b"exit"); print(p.recvall(timeout=2).decode()); p.close()')
    
    patched_py = solve_py.parent / "_patched_solve.py"
    patched_py.write_text(patched)

    print(f"[*] Running exploit under DynamoRIO (timeout={timeout}s)")
    print(f"    solve_script = {solve_py}")
    print(f"    binary       = {target_binary}")
    print(f"    drrun   = {drrun}")
    print(f"    tracer  = {tracer_so}")
    print(f"    log     = {log_path}")

    try:
        subprocess.run(
            ["python3", str(patched_py), "LOCAL"],
            timeout=timeout, capture_output=False,
        )
    except subprocess.TimeoutExpired:
        print(f"[!] Timed out after {timeout}s — using log collected so far.")
    except FileNotFoundError as e:
        print(f"[!] {e}"); sys.exit(1)
    finally:
        wrapper.unlink(missing_ok=True)
        patched_py.unlink(missing_ok=True)

    if not log_path.exists():
        print("[!] Log not created — DynamoRIO may have failed.")
        sys.exit(1)

    print(f"[OK] Log written: {log_path}  ({log_path.stat().st_size} bytes)")

# ──────────────────────────────────────────────────────────────────────────────
# Step 3 – Parse log
# ──────────────────────────────────────────────────────────────────────────────

class MemoryMap:
    def __init__(self):
        self.modules = [] # list of (name, start, end)
        self.heap_min = 0xffffffffffffffff
        self.heap_max = 0

    def add_module(self, name, start, end):
        # Handle potential 0x0x or redundant 0x
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

            if etype == "Leak":
                from_heap = False
                ev_addr_int = int(addr, 16)
                for chunk_addr, chunk_size in active_chunks.items():
                    c_addr_int = int(chunk_addr, 16)
                    if c_addr_int <= ev_addr_int < (c_addr_int + chunk_size):
                        from_heap = True
                        break
                
                is_ptr = mmap.is_in_module(content, "libc") or mmap.is_in_heap(content)
                if not from_heap and not is_ptr:
                    continue
                if any(c in content for c in ("0x312e", "0x322e", "0x332e")):
                    continue

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

# ──────────────────────────────────────────────────────────────────────────────
# Step 4 – Annotate
# ──────────────────────────────────────────────────────────────────────────────

def annotate(events: list[dict], mmap: MemoryMap) -> list[dict]:
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
            if mmap.is_in_module(content, "libc"): notes.append("libc_ptr_candidate")
            elif mmap.is_in_heap(content): notes.append("heap_ptr_candidate")
        elif t == "Copy":
            notes.append(f"n={h_size}")
        elif t == "Read":
            notes.append(f"len={h_size}")
            if mmap.is_in_heap(ev["addr"]): notes.append("heap_read")
            if content and content != "0x0000000000000000":
                if mmap.is_in_module(content, "libc"): notes.append("libc_ptr_candidate")
                elif mmap.is_in_heap(content): notes.append("heap_ptr_candidate")
            
        if notes:
            ev["note"] = ", ".join(notes)
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
    p = argparse.ArgumentParser(description="AutoPwn Module 2 Runner (DynamoRIO)")
    p.add_argument("--drrun",      type=Path, default=DRRUN)
    p.add_argument("--tracer-so",  type=Path, default=TRACER_SO)
    p.add_argument("--tracer-dir", type=Path, default=TRACER_DIR)
    p.add_argument("--solve",      type=Path, default=SOLVE_PY)
    p.add_argument("--log",        type=Path, default=LOG_PATH)
    p.add_argument("--out",        type=Path, default=OUTPUT_JSON)
    p.add_argument("--timeout",    type=int,  default=60)
    p.add_argument("--skip-build", action="store_true")
    p.add_argument("--target",     type=Path, required=True)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    print("=" * 60)
    print("  AutoPwn – Module 2 Runner  [DynamoRIO]")
    print("=" * 60)

    if args.skip_build:
        if not args.tracer_so.exists():
            print(f"[!] {args.tracer_so} not found."); sys.exit(1)
        print(f"[*] Using existing {args.tracer_so}")
    else:
        build_tracer(args.tracer_dir, args.drrun)

    run_exploit(args.tracer_so, args.solve, args.log, args.drrun, args.target, args.timeout)
    events, mmap = parse_log(args.log, args.target.name)
    events = annotate(events, mmap)
    save_json(events, args.out)

    counts = Counter(e["type"] for e in events)
    print("\n── Event summary ──────────────────────────────")
    for etype, cnt in sorted(counts.items()):
        print(f"   {etype:<10} {cnt}")
    notes_found = [e for e in events if "note" in e]
    if notes_found:
        print("\n── Annotated events ───────────────────────────")
        for e in notes_found:
            print(f"   seq={e['seq']:<5} {e['type']:<8} addr={e['addr']}  → {e['note']}")
    print("=" * 60)


if __name__ == "__main__":
    main()
