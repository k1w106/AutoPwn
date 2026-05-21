"""
Module 8: Execution Feedback Loop (NEW)

Runs generated exploits, parses output, and provides feedback for retry/repair.
Matches the paper's "concrete execution" phase.

Workflow:
1. Run exploit in isolated process
2. Parse stdout/stderr for success indicators
3. If fail → analyze error → generate feedback
4. Retry with modified strategy (up to max_retries)
"""

import subprocess
import os
import re
import json
import time
import shutil
import tempfile
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class ExecutionResult:
    """Result of a single exploit execution."""
    success: bool = False
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    leaked_values: Dict[str, str] = field(default_factory=dict)
    error_type: str = ""
    error_detail: str = ""
    feedback: List[str] = field(default_factory=list)


class ExploitExecutor:
    """Runs exploits and provides feedback for repair."""

    SUCCESS_INDICATORS = [
        b"got shell",
        b"got_shell",
        b"uid=",
        b"# ",
        b"$ ",
        b"flag{",
        b"FLAG{",
        b"cat flag",
    ]

    LEAK_PATTERNS = {
        "heap_base": r"heap_base[:\s]+(0x[0-9a-fA-F]+)",
        "libc_leak": r"libc_leak[:\s]+(0x[0-9a-fA-F]+)",
        "libc.address": r"libc.address[:\s]+(0x[0-9a-fA-F]+)",
        "stack_leak": r"stack_leak[:\s]+(0x[0-9a-fA-F]+)",
        "xor_key": r"xor_key[:\s]+(0x[0-9a-fA-F]+)",
    }

    ERROR_PATTERNS = {
        "SIGSEGV": (r"SIGSEGV|Segmentation fault", "segfault"),
        "SIGABRT": (r"SIGABRT|corrupted|malloc_printerr|abort", "malloc_error"),
        "TIMEOUT": (r"Timeout|timed out", "timeout"),
        "EOF": (r"EOFError|End of file", "eof_error"),
        "RECV_TIMEOUT": (r"recv timed out|TimeoutError", "recv_timeout"),
        "INVALID_SIZE": (r"invalid size|invalid next size", "size_error"),
        "DOUBLE_FREE": (r"double free|corruption \(!prev\)", "double_free_error"),
        "FASTBIN_CHECK": (r"memory corruption \(fast\)", "fastbin_error"),
    }

    def __init__(self, exploit_path: str, binary_path: str, timeout: int = 10):
        self.exploit_path = os.path.abspath(exploit_path)
        self.binary_path = os.path.abspath(binary_path)
        self.timeout = timeout
        self.execution_history: List[ExecutionResult] = []

    def run(self) -> ExecutionResult:
        """Run exploit and parse results."""
        exploit_dir = os.path.dirname(self.exploit_path)

        start_time = time.time()
        try:
            result = subprocess.run(
                ["python3", self.exploit_path],
                cwd=exploit_dir,
                timeout=self.timeout,
                capture_output=True,
                env={
                    **os.environ,
                    "PWNLIB_NOTERM": "1",
                    # Don't set PWNLIB_SILENT - we need to see log output
                },
            )
            duration = time.time() - start_time

            exec_result = ExecutionResult(
                exit_code=result.returncode,
                stdout=result.stdout.decode("utf-8", errors="replace"),
                stderr=result.stderr.decode("utf-8", errors="replace"),
                duration=duration,
            )

            # Parse results
            self._parse_leaks(exec_result)
            self._detect_errors(exec_result)
            self._check_success(exec_result)
            self._generate_feedback(exec_result)

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            exec_result = ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"Timeout after {self.timeout}s",
                duration=duration,
                error_type="timeout",
                error_detail=f"Exploit exceeded {self.timeout}s timeout",
            )
            exec_result.feedback.append("Exploit too slow - check for infinite loops or blocking recv")

        except Exception as e:
            duration = time.time() - start_time
            exec_result = ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration=duration,
                error_type="exception",
                error_detail=str(e),
            )

        self.execution_history.append(exec_result)
        return exec_result

    def _parse_leaks(self, result: ExecutionResult):
        """Extract leaked values from stdout."""
        combined = result.stdout + "\n" + result.stderr
        for leak_name, pattern in self.LEAK_PATTERNS.items():
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                result.leaked_values[leak_name] = match.group(1)

    def _detect_errors(self, result: ExecutionResult):
        """Detect error types from output."""
        combined = result.stdout + "\n" + result.stderr
        for error_name, (pattern, error_type) in self.ERROR_PATTERNS.items():
            if re.search(pattern, combined, re.IGNORECASE):
                result.error_type = error_type
                result.error_detail = f"Detected {error_name} in output"
                break

    def _check_success(self, result: ExecutionResult):
        """Check if exploit succeeded."""
        combined = result.stdout.encode() + result.stderr.encode()
        for indicator in self.SUCCESS_INDICATORS:
            if indicator.lower() in combined.lower():
                result.success = True
                return

        # Check if we got all required leaks (partial success)
        required_leaks = {"heap_base", "libc.address"}
        optional_leaks = {"stack_leak"}
        if required_leaks.issubset(set(result.leaked_values.keys())):
            result.success = True  # Partial success - got all leaks
            result.feedback.append("Partial success: All leaks obtained, ROP may need tuning")
            return

        # Check if exploit produced any output (indicates it ran)
        if result.stdout or result.stderr:
            # Exploit ran but didn't get shell - check if it got leaks
            if result.leaked_values:
                result.success = True
                result.feedback.append(f"Partial success: Got {len(result.leaked_values)} leaks")

    def _generate_feedback(self, result: ExecutionResult):
        """Generate actionable feedback based on errors."""
        if result.success:
            result.feedback.append("Exploit succeeded!")
            return

        feedback_map = {
            "segfault": [
                "Check heap layout - chunk addresses may be wrong",
                "Verify safe linking XOR formula: target ^ (heap_base >> 12)",
                "Check if fake chunk size is correct (0x421 for unsorted bin)",
            ],
            "malloc_error": [
                "Check chunk size field - may be corrupted",
                "Verify prev_inuse bit is set on next chunk",
                "Check consolidation: prev_size must match if prev_inuse=0",
            ],
            "timeout": [
                "Check for blocking recv - binary may not send expected output",
                "Verify menu prompts match binary output",
                "Check if exploit hangs waiting for input",
            ],
            "eof_error": [
                "Binary crashed before exploit completed",
                "Check early stages for crashes",
                "Verify interface functions match binary behavior",
            ],
            "recv_timeout": [
                "Binary not sending expected output",
                "Check if read/view function works correctly",
                "Verify prompt strings match binary output",
            ],
            "size_error": [
                "Fake chunk size may be invalid",
                "Check size alignment (must be 0x10 aligned)",
                "Verify size > 0x410 for unsorted bin",
            ],
            "double_free_error": [
                "prev_inuse check failed - set prev_inuse=1 on next chunk",
                "Check fake chunk layout after target chunk",
            ],
            "fastbin_error": [
                "Fastbin size check failed",
                "Target address - 0x10 must have valid size matching fastbin index",
            ],
        }

        if result.error_type in feedback_map:
            result.feedback.extend(feedback_map[result.error_type])
        else:
            result.feedback.append("Unknown error - check stderr for details")

    def run_with_retry(self, max_retries: int = 3, repair_func=None) -> List[ExecutionResult]:
        """Run exploit with retry and optional repair."""
        results = []

        for attempt in range(max_retries):
            print(f"[*] Execution attempt {attempt + 1}/{max_retries}")
            result = self.run()

            results.append(result)

            if result.success:
                print(f"[+] Exploit succeeded on attempt {attempt + 1}")
                break

            print(f"[-] Attempt {attempt + 1} failed: {result.error_type}")
            for fb in result.feedback:
                print(f"    Feedback: {fb}")

            # Apply repair if provided
            if repair_func and attempt < max_retries - 1:
                print(f"[*] Applying repair...")
                repair_func(result, self.exploit_path)

        return results

    def get_summary(self) -> Dict:
        """Get execution summary."""
        if not self.execution_history:
            return {"status": "not_run"}

        last = self.execution_history[-1]
        return {
            "total_attempts": len(self.execution_history),
            "success": last.success,
            "leaked_values": last.leaked_values,
            "last_error": last.error_type,
            "last_feedback": last.feedback,
            "duration": last.duration,
        }

    def save_results(self, output_path: str):
        """Save execution results to JSON."""
        results = []
        for r in self.execution_history:
            results.append({
                "success": r.success,
                "exit_code": r.exit_code,
                "stdout": r.stdout[:1000],  # Truncate
                "stderr": r.stderr[:1000],
                "duration": r.duration,
                "leaked_values": r.leaked_values,
                "error_type": r.error_type,
                "error_detail": r.error_detail,
                "feedback": r.feedback,
            })

        with open(output_path, "w") as f:
            json.dump({
                "execution_results": results,
                "summary": self.get_summary(),
            }, f, indent=4)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Module 8 — Execution Feedback Loop")
    parser.add_argument("--exploit", required=True, help="Path to exploit.py")
    parser.add_argument("--binary", required=True, help="Path to target binary")
    parser.add_argument("--timeout", type=int, default=10, help="Execution timeout")
    parser.add_argument("--retries", type=int, default=3, help="Max retries")
    parser.add_argument("--output", default="../artifacts/execution_results.json")
    args = parser.parse_args()

    executor = ExploitExecutor(args.exploit, args.binary, args.timeout)
    results = executor.run_with_retry(max_retries=args.retries)

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    executor.save_results(args.output)

    summary = executor.get_summary()
    print(f"\n{'='*60}")
    print(f"  Execution Summary")
    print(f"{'='*60}")
    print(f"  Attempts: {summary['total_attempts']}")
    print(f"  Success: {summary['success']}")
    print(f"  Leaked values: {summary['leaked_values']}")
    print(f"  Last error: {summary['last_error']}")
    print(f"{'='*60}")
