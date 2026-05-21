"""
Module 9: Taint Analysis (NEW)

Tracks data flow from user input to vulnerability points.
Provides granular understanding of how input affects heap state.

Workflow:
1. Parse trace events to identify input sources
2. Track data flow through heap operations
3. Identify taint propagation paths
4. Generate taint graph showing input → vulnerability flow
"""

import json
import os
import argparse
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class TaintSource:
    """Source of tainted data."""
    source_type: str  # "stdin", "file", "network", "env"
    offset: int = 0
    size: int = 0
    data: bytes = b""


@dataclass
class TaintSink:
    """Destination where tainted data is used."""
    sink_type: str  # "heap_write", "heap_read", "free", "alloc"
    address: int = 0
    size: int = 0
    operation: str = ""


@dataclass
class TaintPath:
    """Complete taint propagation path."""
    source: TaintSource
    sink: TaintSink
    intermediate_steps: List[dict] = field(default_factory=list)
    taint_type: str = ""  # "direct", "indirect", "control"


class TaintAnalyzer:
    """Tracks data flow from input to vulnerability."""

    def __init__(self, trace_events: List[dict], critical_vars: dict = None):
        self.trace_events = trace_events
        self.critical_vars = critical_vars or {}
        self.taint_sources: List[TaintSource] = []
        self.taint_sinks: List[TaintSink] = []
        self.taint_paths: List[TaintPath] = []
        self.chunk_taint: Dict[str, Set[str]] = {}  # chunk_addr -> taint labels
        self.taint_graph: Dict[str, List[str]] = {}  # node -> [children]

    def _identify_taint_sources(self):
        """Identify all input sources in trace."""
        for i, ev in enumerate(self.trace_events):
            etype = ev.get("type", "")
            note = ev.get("note", "").lower()

            # User input via read/recv
            if etype in ("Read", "recv", "Copy"):
                self.taint_sources.append(TaintSource(
                    source_type="stdin",
                    offset=i,
                    size=ev.get("size", 0),
                ))

            # File input
            if "file" in note or "input" in note:
                self.taint_sources.append(TaintSource(
                    source_type="file",
                    offset=i,
                    size=ev.get("size", 0),
                ))

    def _identify_taint_sinks(self):
        """Identify all vulnerability sinks."""
        for i, ev in enumerate(self.trace_events):
            etype = ev.get("type", "")
            addr = int(ev.get("addr", "0x0"), 16)
            size = ev.get("size", 0)

            if etype == "Alloc":
                self.taint_sinks.append(TaintSink(
                    sink_type="alloc",
                    address=addr,
                    size=size,
                    operation=f"malloc({size})",
                ))
            elif etype == "Free":
                self.taint_sinks.append(TaintSink(
                    sink_type="free",
                    address=addr,
                    size=size,
                    operation=f"free({hex(addr)})",
                ))
            elif etype in ("Write", "Copy"):
                self.taint_sinks.append(TaintSink(
                    sink_type="heap_write",
                    address=addr,
                    size=size,
                    operation=f"write({hex(addr)}, {size})",
                ))
            elif etype in ("Read", "Leak"):
                self.taint_sinks.append(TaintSink(
                    sink_type="heap_read",
                    address=addr,
                    size=size,
                    operation=f"read({hex(addr)}, {size})",
                ))

    def _build_taint_graph(self):
        """Build taint propagation graph."""
        self.taint_graph = {"input": []}

        current_chunk = None
        for i, ev in enumerate(self.trace_events):
            etype = ev.get("type", "")
            addr = ev.get("addr", "0x0")
            size = ev.get("size", 0)
            content = ev.get("content", "")

            node_id = f"ev_{i}_{etype}"

            if etype == "Alloc":
                # New chunk created - may receive tainted data
                if current_chunk:
                    self.taint_graph.setdefault(current_chunk, []).append(node_id)
                current_chunk = addr
                self.taint_graph["input"].append(node_id)
                self.chunk_taint[addr] = {"input"}

            elif etype in ("Write", "Copy"):
                # Data written to chunk - propagate taint
                if current_chunk:
                    self.taint_graph.setdefault(current_chunk, []).append(node_id)
                    if current_chunk in self.chunk_taint:
                        self.chunk_taint[addr] = self.chunk_taint.get(addr, set()) | self.chunk_taint[current_chunk]

            elif etype == "Free":
                # Chunk freed - taint may affect free behavior
                if addr in self.chunk_taint:
                    self.taint_graph.setdefault(addr, []).append(node_id)

            elif etype in ("Read", "Leak"):
                # Data read from chunk - taint propagates to output
                if addr in self.chunk_taint:
                    self.taint_graph.setdefault(addr, []).append(node_id)
                    self.taint_graph.setdefault(node_id, []).append("output")

    def _find_taint_paths(self):
        """Find complete taint propagation paths."""
        for source in self.taint_sources:
            for sink in self.taint_sinks:
                # Check if there's a path from source to sink
                path = self._find_path(source, sink)
                if path:
                    taint_path = TaintPath(
                        source=source,
                        sink=sink,
                        intermediate_steps=path,
                        taint_type=self._classify_taint(source, sink),
                    )
                    self.taint_paths.append(taint_path)

    def _find_path(self, source: TaintSource, sink: TaintSink) -> List[dict]:
        """Find path from source to sink in taint graph."""
        # Simple BFS through events
        path = []
        for i, ev in enumerate(self.trace_events):
            if source.offset <= i <= source.offset + 5:  # Within 5 events of source
                path.append({
                    "event_index": i,
                    "type": ev.get("type", ""),
                    "addr": ev.get("addr", ""),
                    "size": ev.get("size", 0),
                })
        return path

    def _classify_taint(self, source: TaintSource, sink: TaintSink) -> str:
        """Classify taint type."""
        if sink.sink_type in ("heap_write", "alloc"):
            return "data_taint"  # Tainted data written to heap
        elif sink.sink_type == "free":
            return "control_taint"  # Tainted data affects free behavior
        elif sink.sink_type == "heap_read":
            return "info_leak"  # Tainted data leaks information
        return "unknown"

    def _identify_vulnerability_paths(self) -> List[dict]:
        """Identify paths that lead to exploitable conditions."""
        vuln_paths = []

        for path in self.taint_paths:
            vuln_type = None

            # Tainted data → heap write → UAF
            if path.taint_type == "data_taint" and path.sink.sink_type == "heap_write":
                # Check if there's a subsequent free without null check
                for ev in self.trace_events:
                    if ev.get("type") == "Free" and ev.get("addr") == hex(path.sink.address):
                        vuln_type = "uaf_write"
                        break

            # Tainted data → free → double free
            if path.taint_type == "control_taint" and path.sink.sink_type == "free":
                free_count = 0
                for ev in self.trace_events:
                    if ev.get("type") == "Free" and ev.get("addr") == hex(path.sink.address):
                        free_count += 1
                if free_count > 1:
                    vuln_type = "double_free"

            # Tainted data → read → info leak
            if path.taint_type == "info_leak":
                vuln_type = "info_leak"

            if vuln_type:
                vuln_paths.append({
                    "vulnerability": vuln_type,
                    "source_offset": path.source.offset,
                    "sink_address": hex(path.sink.address),
                    "path_length": len(path.intermediate_steps),
                    "taint_type": path.taint_type,
                })

        return vuln_paths

    def analyze(self) -> dict:
        """Run full taint analysis."""
        self._identify_taint_sources()
        self._identify_taint_sinks()
        self._build_taint_graph()
        self._find_taint_paths()

        vuln_paths = self._identify_vulnerability_paths()

        return {
            "taint_sources": [
                {"type": s.source_type, "offset": s.offset, "size": s.size}
                for s in self.taint_sources
            ],
            "taint_sinks": [
                {"type": s.sink_type, "address": hex(s.address), "size": s.size, "operation": s.operation}
                for s in self.taint_sinks
            ],
            "taint_paths": [
                {
                    "source_offset": p.source.offset,
                    "sink_address": hex(p.sink.address),
                    "taint_type": p.taint_type,
                    "path_length": len(p.intermediate_steps),
                }
                for p in self.taint_paths
            ],
            "vulnerability_paths": vuln_paths,
            "taint_graph": {k: v[:10] for k, v in self.taint_graph.items()},  # Truncate
            "summary": {
                "total_sources": len(self.taint_sources),
                "total_sinks": len(self.taint_sinks),
                "total_paths": len(self.taint_paths),
                "vulnerability_paths": len(vuln_paths),
                "tainted_chunks": len(self.chunk_taint),
            },
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Module 9 — Taint Analysis")
    parser.add_argument("--trace", default="../artifacts/trace_events.json")
    parser.add_argument("--critical", default="../artifacts/critical_vars.json")
    parser.add_argument("--output", default="../artifacts/taint_results.json")
    args = parser.parse_args()

    if not os.path.exists(args.trace):
        print(f"[!] Trace file not found: {args.trace}")
        exit(1)

    with open(args.trace, "r") as f:
        trace_events = json.load(f)

    critical_vars = {}
    if os.path.exists(args.critical):
        with open(args.critical, "r") as f:
            critical_vars = json.load(f)

    analyzer = TaintAnalyzer(trace_events, critical_vars)
    result = analyzer.analyze()

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(result, f, indent=4)

    print(f"\n[OK] Taint analysis saved to {args.output}")
    print(f"     Sources: {result['summary']['total_sources']}")
    print(f"     Sinks: {result['summary']['total_sinks']}")
    print(f"     Taint paths: {result['summary']['total_paths']}")
    print(f"     Vulnerability paths: {result['summary']['vulnerability_paths']}")
