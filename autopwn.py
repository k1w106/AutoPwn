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
            # Use absolute path for python3 if in venv
            python_exe = sys.executable or "python3"
            full_command = f"{python_exe} {command}"
            
            result = subprocess.run(full_command, shell=True, check=True, capture_output=True, text=True, cwd=cwd)
            elapsed = time.time() - start_time
            print(f"      OK ({elapsed:.2f}s)")
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"      FAILED: {e}")
            print(f"      Error: {e.stderr}")
            # print(f"      Output: {e.stdout}") # Uncomment for debugging
            sys.exit(1)

    def run(self):
        print("\n" + "="*60)
        print("  AUTOPWN FRAMEWORK: Artifact-Assisted Exploit Generation")
        print("="*60)
        print(f"Target: {os.path.basename(self.target)}")
        print("-" * 60)
        
        # Step 1: NLP Extraction (Module 1)
        self.run_stage("Artifact Extraction (NLP)", "extract_vars.py", cwd=os.path.join(self.root_dir, "core", "nlp_engine"))
        # Step 2: Runtime Tracing (Module 2)
        self.run_stage("Runtime Experience Tracing", f"runner.py --target {self.target}", cwd=os.path.join(self.root_dir, "core", "tracer"))
        # Step 3: Knowledge Fusion (Module 3)
        self.run_stage("Knowledge Fusion (ESM)", "esm.py", cwd=os.path.join(self.root_dir, "core", "knowledge_fusion"))
        # Step 4: Exploit Planning (Module 4)
        self.run_stage("Exploit Planning (Evolutionary)", "planner.py", cwd=os.path.join(self.root_dir, "core", "planner"))
        # Step 5: Exploit Generation (Module 5)
        binary_name = os.path.basename(self.target)
        self.run_stage("Code Generation (Codegen)", f"synthesizer.py --binary {binary_name}", cwd=os.path.join(self.root_dir, "core", "codegen"))
        print("-" * 60)

        self.log("SYNC", "Collecting all artifacts into outputs/")
        
        # Copy critical internal artifacts to user-visible output
        for filename in ["critical_vars.json", "trace_events.json", "esm_output.json", "final_plan.json"]:
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
    parser = argparse.ArgumentParser(description="AutoPwn Orchestrator")
    parser.add_argument("binary", help="Path to the target binary")
    args = parser.parse_args()
    
    if not os.path.exists(args.binary):
        print(f"Error: Binary {args.binary} not found.")
        sys.exit(1)
        
    framework = AutoPwnFramework(args.binary)
    framework.run()
