import subprocess
import os
import re
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class CapabilityResult:
    cap_name: str
    passed: int = 0
    total: int = 0
    leaked_value: Optional[str] = None

    @property
    def confidence(self) -> float:
        return self.passed / max(self.total, 1)

    @property
    def robust(self) -> bool:
        return self.confidence >= 0.66


@dataclass
class VerificationReport:
    results: Dict[str, CapabilityResult] = field(default_factory=dict)
    stdout: str = ""
    duration: float = 0.0

    def record(self, cap_name: str, passed: bool):
        if cap_name not in self.results:
            self.results[cap_name] = CapabilityResult(cap_name=cap_name)
        self.results[cap_name].total += 1
        if passed:
            self.results[cap_name].passed += 1

    def record_leak(self, cap_name: str, value: str):
        if cap_name not in self.results:
            self.results[cap_name] = CapabilityResult(cap_name=cap_name)
        self.results[cap_name].leaked_value = value
        self.results[cap_name].passed += 1
        self.results[cap_name].total += 1

    def merit(self, cap_name: str, value: str):
        """Record an implausible leaked value (wrong address range)."""
        if cap_name not in self.results:
            self.results[cap_name] = CapabilityResult(cap_name=cap_name)
        # Count as failed, but note the value
        self.results[cap_name].total += 1
        if not self.results[cap_name].leaked_value:
            self.results[cap_name].leaked_value = f"implausible:{value}"

    def all_robust(self) -> bool:
        if not self.results:
            return False
        return all(r.robust for r in self.results.values())

    def summary(self) -> List[str]:
        lines = []
        for name, r in self.results.items():
            status = "+" if r.robust else "-"
            lines.append(f"  {status} {name}: {r.passed}/{r.total} "
                         f"(conf={r.confidence:.2f})"
                         f"{' leak='+r.leaked_value if r.leaked_value else ''}")
        return lines
class CapabilityVerifier:
    LEAK_PATTERNS = {
        "heap_base": r"heap_base[:\s]+(0x[0-9a-fA-F]+)",
        "libc_leak": r"libc_leak[:\s]+(0x[0-9a-fA-F]+)",
        "libc.address": r"libc\.address[:\s]+(0x[0-9a-fA-F]+)",
        "stack_leak": r"stack_leak[:\s]+(0x[0-9a-fA-F]+)",
        "xor_key": r"xor_key[:\s]+(0x[0-9a-fA-F]+)",
    }

    CRASH_PATTERNS = [
        re.compile(r"SIGSEGV|Segmentation fault", re.IGNORECASE),
        re.compile(r"SIGABRT|corrupted|malloc_printerr|abort", re.IGNORECASE),
        re.compile(r"Timeout|timed out", re.IGNORECASE),
        re.compile(r"EOFError|End of file", re.IGNORECASE),
        re.compile(r"TypeError|ValueError|KeyError|IndexError|NameError|AttributeError", re.IGNORECASE),
        re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
        re.compile(r"pwnlib.*Error", re.IGNORECASE),
    ]

    def verify(self, exploit_path: str, binary_path: str,
               timeout: int = 15, runs: int = 3) -> VerificationReport:
        report = VerificationReport()
        start_time = time.time()

        for run in range(runs):
            try:
                result = subprocess.run(
                    ["python3", exploit_path],
                    cwd=os.path.dirname(exploit_path),
                    timeout=timeout,
                    capture_output=True,
                    env={**os.environ, "PWNLIB_NOTERM": "1"},
                )
                stdout = result.stdout.decode("utf-8", errors="replace")
                stderr = result.stderr.decode("utf-8", errors="replace")
                combined = stdout + "\n" + stderr

                has_crash = any(
                    pat.search(combined)
                    for pat in self.CRASH_PATTERNS
                )

                if has_crash:
                    for cap_name in self.LEAK_PATTERNS:
                        report.record(cap_name, False)
                    report.record("exec", False)
                    continue

                found_leak = False
                for cap_name, pattern in self.LEAK_PATTERNS.items():
                    match = re.search(pattern, combined, re.IGNORECASE)
                    if match:
                        leaked_val_str = match.group(1)
                        leaked_val = int(leaked_val_str, 16)
                        # Validate address plausibility
                        if self._is_plausible(cap_name, leaked_val):
                            report.record_leak(cap_name, leaked_val_str)
                            found_leak = True
                        else:
                            report.record(cap_name, False)
                            report.merit(cap_name, leaked_val_str)

                if found_leak:
                    report.record("ok", True)
                else:
                    report.record("no_leak", False)

            except subprocess.TimeoutExpired:
                for cap_name in self.LEAK_PATTERNS:
                    report.record(cap_name, False)
            except Exception:
                for cap_name in self.LEAK_PATTERNS:
                    report.record(cap_name, False)

        report.duration = time.time() - start_time
        return report

    @staticmethod
    def _is_plausible(cap_name: str, value: int) -> bool:
        """Validate leaked address looks like the right region."""
        if value == 0:
            return False
        hi = (value >> 40) & 0xff
        if cap_name in ("heap_base", "xor_key"):
            return hi in (0x55, 0x56, 0x5)  # PIE/heap region
        if cap_name in ("libc_leak", "libc.address"):
            return hi in (0x7f, 0x7e, 0x7d, 0x70, 0x71, 0x72, 0x73)  # mmap/libc region
        if cap_name == "stack_leak":
            return hi in (0x7f, 0x7e, 0x7d)  # stack region (high addresses)
        return True  # Unknown cap — accept any non-zero value

    @staticmethod
    def save_report(report: VerificationReport, output_path: str):
        data = {
            "summary": {"all_robust": report.all_robust(),
                        "duration": report.duration},
            "results": {
                name: {
                    "passed": r.passed,
                    "total": r.total,
                    "confidence": r.confidence,
                    "robust": r.robust,
                    "leaked_value": r.leaked_value,
                }
                for name, r in report.results.items()
            },
        }
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
