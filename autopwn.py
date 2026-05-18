import os
import sys
import argparse
import subprocess
import json
import time
import shutil

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

        # Step 2: Runtime Tracing (Module 2)
        angr_flag = "--angr" if use_angr else ""
        self.run_stage("Runtime Experience Tracing",
                       f"runner.py --target {self.target} {angr_flag}",
                       cwd=os.path.join(self.root_dir, "core", "tracer"))

        # Step 3: Operation Generalization (Module 3 — NEW)
        self.run_stage("Operation Generalization",
                       f"operation_generalizer.py",
                       cwd=os.path.join(self.root_dir, "core", "generalizer"))

        # Step 4: Knowledge Fusion / Composite ESM (Module 4)
        self.run_stage("Knowledge Fusion (Composite ESM)",
                       "esm.py",
                       cwd=os.path.join(self.root_dir, "core", "knowledge_fusion"))

        # Step 5: angr Symbolic Execution (Module 5 — NEW)
        self.run_stage("angr Symbolic Execution",
                       f"angr_executor.py --binary {self.target}",
                       cwd=os.path.join(self.root_dir, "core", "symbolic_executor"))

        # Step 6: Exploit Planning (Module 6 — Evolutionary DFS)
        self.run_stage("Exploit Planning (Evolutionary DFS)",
                       f"planner.py --binary {self.target}",
                       cwd=os.path.join(self.root_dir, "core", "planner"))

        # Step 7: Exploit Generation (Module 7 — Synthesizer)
        binary_name = os.path.basename(self.target)
        local_solve = os.path.join(self.target_dir, "solve.py")
        solve_arg = ""
        if os.path.exists(local_solve):
            solve_arg = f"--solve {os.path.abspath(local_solve)}"

        libc_arg = ""
        for libc_name in ["libc.so.6", "libc.so"]:
            libc_path = os.path.join(self.target_dir, libc_name)
            if os.path.exists(libc_path):
                libc_arg = f"--libc {os.path.abspath(libc_path)}"
                break

        self.run_stage("Code Generation (Synthesizer)",
                       f"synthesizer.py --binary {binary_name} {solve_arg} {libc_arg}",
                       cwd=os.path.join(self.root_dir, "core", "codegen"))

        print("-" * 60)

        self.log("SYNC", "Collecting all artifacts into outputs/")

        # Copy all internal artifacts to user-visible output
        for filename in ["critical_vars.json", "trace_events.json",
                        "generalized_actions.json", "esm_output.json",
                        "symbolic_results.json", "final_plan.json"]:
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
