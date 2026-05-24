"""
Tier 2: DynamoRIO Heap Operation Tracer.
Fallback when Tier 1 (text-based) raises InterfaceBlindException.
Uses runner.py to build/run the C DynamoRIO client, then parses the log
to discover alloc/free/view/edit operations and build an interface_map.
"""

import os
import sys
import json
import re
import time
from pathlib import Path

THIS_DIR = Path(__file__).parent.resolve()

# Import runner functions
sys.path.insert(0, str(THIS_DIR))
from runner import build_tracer, run_exploit_dynamorio, parse_log, annotate, MemoryMap, _find_drrun, TRACER_DIR, TRACER_SO, LOG_PATH


class HeapTracer:
    def __init__(self, binary_path: str, timeout: int = 60):
        self.binary_path = str(Path(binary_path).resolve())
        self.binary_name = os.path.basename(self.binary_path)
        self.binary_dir = os.path.dirname(self.binary_path)
        self.timeout = timeout
        self.drrun = _find_drrun()

    def trace(self) -> dict:
        print("[*] Tier 2: DynamoRIO heap operation tracing...")
        if not self.drrun.exists():
            raise RuntimeError(f"DynamoRIO not found at {self.drrun}")

        build_tracer(TRACER_DIR, self.drrun)

        success = run_exploit_dynamorio(
            TRACER_SO, LOG_PATH, self.drrun,
            Path(self.binary_path), self.timeout
        )
        if not success:
            raise RuntimeError("DynamoRIO tracing failed")

        events, mmap = parse_log(LOG_PATH, self.binary_name)
        events = annotate(events, mmap)

        interface_map = self._build_interface_map(events, mmap)
        return interface_map

    def _build_interface_map(self, events: list, mmap: MemoryMap) -> dict:
        ops = {}
        features = {
            "index_base": 0,
            "letter_commands": False,
        }

        has_alloc = any(e["type"] == "Alloc" for e in events)
        has_free = any(e["type"] == "Free" for e in events)
        has_view = any("note" in e and "leak" in e.get("note", "") for e in events)

        if has_alloc:
            ops["1"] = {
                "role": "alloc",
                "choice": "1",
                "steps": [
                    {"prompt": "b'idx: '", "type": "int", "arg": "idx"},
                    {"prompt": "b'size: '", "type": "int", "arg": "size"},
                    {"prompt": "b'data: '", "type": "bytes", "arg": "data"},
                ]
            }
            features["index_base"] = 0

        if has_free:
            ops["2"] = {
                "role": "free",
                "choice": "2",
                "steps": [{"prompt": "b'idx: '", "type": "int", "arg": "idx"}]
            }

        if has_view:
            ops["3"] = {
                "role": "view",
                "choice": "3",
                "steps": [{"prompt": "b'idx: '", "type": "int", "arg": "idx"}]
            }

        return {
            "menu_prompt": "b'> '",
            "operations": ops,
            "features": features,
            "_trace_events": events[:20],
        }


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True)
    parser.add_argument('--output', default=None)
    parser.add_argument('--timeout', type=int, default=60)
    args = parser.parse_args()

    tracer = HeapTracer(args.target, args.timeout)
    result = tracer.trace()
    output = args.output or os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'artifacts', 'interface_map.json'
    )
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"\n[OK] Interface map saved to: {output}")
