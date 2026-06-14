import os
import sys
import argparse
import subprocess
import json
import time
import shutil


class AutoPwnFramework:
    def __init__(self, target_binary, mode="primitives", writeup_dir=None):
        self.target = os.path.abspath(target_binary)
        self.target_dir = os.path.dirname(self.target)
        self.root_dir = os.path.dirname(os.path.abspath(__file__))
        self.mode = mode
        self.writeup_dir = writeup_dir

        self.output_dir = os.path.join(self.root_dir, "outputs")
        self.artifacts_dir = os.path.join(self.output_dir, "artifacts")
        self.traces_dir = os.path.join(self.output_dir, "traces")
        self.exploits_dir = os.path.join(self.output_dir, "exploits")

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
            result = subprocess.run(
                f"{python_exe} {command}", shell=True, check=True,
                capture_output=True, text=True, cwd=cwd)
            elapsed = time.time() - start_time
            print(f"      OK ({elapsed:.2f}s)")
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"      FAILED: {e}")
            print(f"      Error: {e.stderr}")
            sys.exit(1)

    def _discover_interface(self):
        from core.tracer.interface_fuzzer import TextInterfaceFuzzer, InterfaceBlindException
        try:
            fuzzer = TextInterfaceFuzzer(self.target, timeout=15)
            result = fuzzer.discover()
            print("      [Tier 1] Text-based interface discovery succeeded")
            return result
        except (ImportError, InterfaceBlindException, Exception) as e:
            print(f"      [Tier 1] {e}")
        return None

    def _run_nlp_engine(self):
        """Module 1: NLP Engine — extract knowledge from writeup files."""
        writeup_dir = self.writeup_dir
        if not writeup_dir:
            writeup_dir = os.path.join(self.root_dir, "data", "writeups")

        if not os.path.isdir(writeup_dir):
            print(f"      [NLP] No writeup directory at {writeup_dir}, skipping")
            return {}

        txt_files = [f for f in os.listdir(writeup_dir) if f.endswith(".txt")]
        if not txt_files:
            print(f"      [NLP] No .txt files in {writeup_dir}, skipping")
            return {}

        self.log("NLP", f"Scanning {len(txt_files)} writeup(s)...")
        try:
            from core.nlp_engine.extract_vars import NLPEngine, scan_file, build_composite

            engine = NLPEngine()
            all_per_writeup = {}

            for filename in sorted(txt_files):
                path = os.path.join(writeup_dir, filename)
                vars_list, states_list = scan_file(path, engine)
                taxonomy = engine.structure_output(vars_list, states_list)
                all_per_writeup[filename] = {
                    "vars": vars_list,
                    "states": states_list,
                    "taxonomy": taxonomy["taxonomy"],
                    "exploit_ir": taxonomy["exploit_ir"],
                }

            composite = build_composite(all_per_writeup, engine)

            # Enrich with knowledge base rules
            try:
                from core.knowledge_base.loader import get_knowledge_base
                kb = get_knowledge_base()
                composite["knowledge_base"] = {
                    "malloc_rules": {
                        "tcache_max_size": kb.get_tcache_info().get("max_size", 0x410),
                        "tcache_max_per_size": kb.get_tcache_info().get("max_per_size", 7),
                    },
                    "active_mitigations": kb.check_mitigations(),
                    "exploit_phases": kb.get_exploit_phases(),
                    "decision_rules": kb.get_decision_rules(),
                }
            except Exception:
                pass

            output_path = os.path.join(self.internal_artifacts, "critical_vars.json")
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(composite, f, indent=2, ensure_ascii=False)

            print(f"      Composite techniques: {composite.get('composite_taxonomy', {}).get('techniques', [])}")
            print(f"      Composite capabilities: {composite.get('composite_taxonomy', {}).get('capabilities', [])}")
            return composite

        except ImportError as e:
            print(f"      [NLP] Module not available: {e}, skipping")
            return {}
        except Exception as e:
            print(f"      [NLP] Error: {e}, skipping")
            return {}

    def _run_tracer(self):
        """Module 2: DynamoRIO Heap Tracer — instrumentalize and trace binary."""
        self.log("TRACER", "Running DynamoRIO heap tracer...")
        try:
            from core.tracer.heap_tracer import HeapTracer

            tracer = HeapTracer(self.target, timeout=60)
            interface_map = tracer.trace()

            output_path = os.path.join(self.internal_artifacts, "trace_events.json")
            log_path = "/tmp/autopwn_trace.log"
            if os.path.exists(log_path):
                import json
                from core.tracer.runner import parse_log, annotate, MemoryMap
                events, mmap = parse_log(log_path, os.path.basename(self.target))
                events = annotate(events, mmap)
                with open(output_path, "w") as f:
                    json.dump(events, f, indent=2, default=str)
                print(f"      Traced {len(events)} events")

            return interface_map

        except ImportError:
            print("      DynamoRIO not available, skipping tracer")
        except RuntimeError as e:
            print(f"      Tracer failed: {e}")
        except Exception as e:
            print(f"      Tracer error: {e}")

        return None

    def _run_generalizer(self):
        """Module 3: Operation Generalizer — generalize trace events."""
        trace_path = os.path.join(self.internal_artifacts, "trace_events.json")
        if not os.path.exists(trace_path):
            return None

        critical_path = os.path.join(self.internal_artifacts, "critical_vars.json")
        critical_vars = {}
        if os.path.exists(critical_path):
            with open(critical_path, "r") as f:
                critical_vars = json.load(f)

        self.log("GENERALIZER", "Generalizing trace operations...")
        try:
            from core.generalizer.operation_generalizer import OperationGeneralizer

            with open(trace_path, "r") as f:
                events = json.load(f)

            generalizer = OperationGeneralizer(events, critical_vars)
            result = generalizer.generalize()

            output_path = os.path.join(self.internal_artifacts, "generalized_actions.json")
            with open(output_path, "w") as f:
                json.dump(result, f, indent=2, default=str)

            print(f"      {result['summary']['total_operations']} operations generalized")
            print(f"      Symbolic objects: {list(result['summary']['symbolic_objects'].keys())}")
            return result

        except ImportError as e:
            print(f"      Generalizer unavailable: {e}")
        except Exception as e:
            print(f"      Generalizer error: {e}")

        return None

    def _find_libc_ld(self):
        libc_path = None
        for name in ["libc.so.6", "libc.so"]:
            p = os.path.join(self.target_dir, name)
            if os.path.exists(p):
                libc_path = p
                break
        ld_path = None
        for prefix in ["ld-linux-x86-64.so.2", "ld-"]:
            for f in os.listdir(self.target_dir):
                if f.startswith(prefix):
                    ld_path = os.path.join(self.target_dir, f)
                    break
            if ld_path:
                break
        return libc_path, ld_path

    def _save_artifacts(self, plan, env, verifier_report=None):
        plan_path = os.path.join(self.internal_artifacts, "final_plan.json")
        with open(plan_path, "w") as f:
            json.dump(plan.to_dict() if hasattr(plan, 'to_dict') else plan, f, indent=2)

        for fname in ["final_plan.json", "verification_report.json"]:
            src = os.path.join(self.internal_artifacts, fname)
            if os.path.exists(src):
                shutil.copy(src, self.artifacts_dir)

        shutil.copy2(self.target, self.exploits_dir)
        for lib in ["libc.so.6", "ld-linux-x86-64.so.2"]:
            lib_path = os.path.join(self.target_dir, lib)
            if os.path.exists(lib_path):
                shutil.copy2(lib_path, self.exploits_dir)

    def run(self):
        print("\n" + "=" * 60)
        print("  AUTOPWN: Capability-Driven Primitive Exploit Generation")
        print(f"  Mode: {self.mode}")
        print("=" * 60)
        print(f"Target: {os.path.basename(self.target)}")
        print("-" * 60)

        # Phase 0: NLP Engine — extract knowledge from writeups
        self.log("PHASE 0", "Running NLP Engine on writeups...")
        nlp_composite = self._run_nlp_engine()

        # Phase 1: Interface Discovery
        self.log("PHASE 1", "Discovering binary interface...")
        interface_map = self._discover_interface()
        if not interface_map:
            # Try tracer-based discovery
            tracer_map = self._run_tracer()
            if tracer_map:
                interface_map = tracer_map
            else:
                print("      Using default interface (4 ops, no discovery)")
                interface_map = {"operations": {
                    "1": {"role": "alloc", "steps": [{"arg": "idx", "prompt": "b': '"}, {"arg": "size", "prompt": "b': '"}, {"arg": "data", "prompt": "b': '"}]},
                    "2": {"role": "free",  "steps": [{"arg": "idx", "prompt": "b': '"}]},
                    "3": {"role": "view",  "steps": [{"arg": "idx", "prompt": "b': '"}]},
                    "4": {"role": "edit",  "steps": [{"arg": "idx", "prompt": "b': '"}, {"arg": "data", "prompt": "b': '"}]},
                }, "menu_prompt": "b'> '",
                   "max_slots": 20}

        libc_path, ld_path = self._find_libc_ld()

        # Phase 2: Environment
        self.log("PHASE 2", "Building environment...")
        from core.analysis.environment import Environment
        env = Environment.build(self.target, libc_path=libc_path,
                                ld_path=ld_path, interface_map=interface_map)
        print(f"      glibc: {env.glibc_version}, safe-linking: {env.safe_linking}, "
              f"hooks: {env.has_hooks}, PIE: {env.pie}, RELRO: {env.relro}")
        print(f"      ops: {sorted(env.available_ops)}, slots: {env.max_slots}")

        # Phase 2.5: Probe actual heap layout from binary
        self.log("PHASE 2.5", "Probing binary heap layout...")
        try:
            from core.analysis.chunk_prober import ChunkProber
            import multiprocessing

            def _probe():
                prober = ChunkProber(self.target, interface_map,
                                     libc_path=libc_path, ld_path=ld_path,
                                     timeout=3)
                return prober.probe()

            # Run probe in a separate process with 8s timeout
            with multiprocessing.Pool(1) as pool:
                layout = pool.apply_async(_probe).get(timeout=8)
            if layout:
                env.chunk_size = layout["chunk_size"]
                env.c0_addr = layout["c0_addr"]
                env.c1_addr = layout["c1_addr"]
                env.c2_addr = layout["c2_addr"]
                if layout.get("heap_base"):
                    env.heap_base = layout["heap_base"]
                print(f"      probed: chunk_size={hex(env.chunk_size)}, "
                      f"c0={hex(env.c0_addr)}, c1={hex(env.c1_addr)}")
            else:
                raise Exception("probe returned None")
        except Exception:
            print(f"      probe skipped (binary timeout) — using chunk_size={hex(env.chunk_size)}")
            # env.chunk_size keeps its default (0x40)

        # Phase 2b: Operation Generalizer (if trace events exist)
        generalized = self._run_generalizer()

        # Phase 3: Bug Detection
        self.log("PHASE 3", "Detecting bugs...")
        from core.analysis.bug_detector import BugDetector
        trace_path = os.path.join(self.internal_artifacts, "trace_events.json")
        trace_events = []
        if os.path.exists(trace_path):
            with open(trace_path) as f:
                trace_events = json.load(f)
        bugs = BugDetector.detect(trace_events, interface_map)

        # Enrich bugs from NLP composite
        if nlp_composite:
            nlp_bugs = nlp_composite.get("composite_taxonomy", {}).get("bugs", [])
            for b in nlp_bugs:
                bugs.add(b, "nlp_composite", 0.6)

        print(f"      bugs: {sorted(bugs.names()) if bugs.names() else 'none (using default)'}")
        if not bugs.names():
            bugs.add("uaf", "default_assumption")
            bugs.add("double_free_possible", "default_assumption")
            bugs.add("potential_uaf", "default_assumption")

        # Phase 4: AbstractHeapState
        self.log("PHASE 4", "Building heap state model...")
        from core.state.heap_state import AbstractHeapState
        from core.state.invariants import HeapInvariant
        state = AbstractHeapState.build_empty(max_slots=env.max_slots)
        for bug_name in bugs.names():
            state.tags.add(bug_name)
        state.tags.add("heap_leak_possible")
        state.tags.add("libc_leak_possible")
        state = state.allocate_at_slot(0, 0x40)
        state = state.free_slot(0)
        if trace_events:
            for ev in trace_events[:8]:
                etype = ev.get("type", "")
                if etype == "Alloc":
                    state = state.allocate_at_slot(ev.get("slot", 0), ev.get("size", 0x40))
                elif etype == "Free":
                    state = state.free_slot(ev.get("slot", 0))
                elif etype == "Read":
                    state = state.view_slot(ev.get("slot", 0))
                elif etype == "Write":
                    state = state.edit_slot(ev.get("slot", 0))
        ok = HeapInvariant.check_all(state)
        if not ok:
            print("      [WARN] Heap invariants violated (non-fatal)")
        print(f"      state: {len(state.slots)} slots, {len(state.regions)} regions, "
              f"{len(state.tags)} tags")

        # Phase 5: Capability Derivation
        self.log("PHASE 5", "Deriving capabilities from state...")
        from core.capabilities.deriver import CapabilityDeriver
        caps = CapabilityDeriver.derive(state)
        print(f"      capabilities: {[c.describe() for c in caps]}")

        # Phase 6: Knowledge Base + Planning
        self.log("PHASE 6", "Querying knowledge base and planning...")
        from core.knowledge_base.loader import get_knowledge_base
        from core.planner.constraint_planner import ConstraintPlanner, ExploitMode

        kb = get_knowledge_base()
        print(f"      KB: {len(kb._get_json_techniques())} techniques, "
              f"{len(kb.parsed_techniques)} parsed how2heap entries")

        plan_mode = ExploitMode.PRIMITIVES_ONLY  # Always use KB-driven primitives
        planner = ConstraintPlanner(kb=kb, mode=plan_mode)
        plan = planner.plan(state, bugs, caps, env)

        if not plan or not plan.stages:
            diagnosis = plan.diagnosis if plan else {"global": "planning returned None"}
            print("[-] No exploit path found through knowledge base.")
            print("    Diagnosis:")
            for k, v in diagnosis.items():
                print(f"      [{k}] {v}")
            sys.exit(1)

        print(f"      target: {plan.target.name} ({plan.target.exploit_type})")
        print(f"      stages: {[s.name for s in plan.stages]}")
        print(f"      techniques: {[s.technique_id for s in plan.stages]}")
        print(f"      confidence: {plan.confidence:.2f}")

        if plan.diagnosis:
            print(f"      warnings:")
            for k, v in plan.diagnosis.items():
                print(f"        [{k}] {v}")

        # Phase 7: Code Generation
        self.log("PHASE 7", "Generating exploit code...")
        from core.codegen.capability_codegen import CapabilityCodegen
        codegen = CapabilityCodegen(plan, interface_map, self.target,
                                     libc_path=libc_path, ld_path=ld_path, kb=kb, env=env)
        exploit_path = os.path.join(self.exploits_dir, "exploit.py")
        codegen.save(exploit_path)
        print(f"      OK — {exploit_path}")
        
        from core.executor.capability_verifier import CapabilityVerifier
        verifier = CapabilityVerifier()
        report = verifier.verify(exploit_path, self.target, timeout=15, runs=3)

        report_path = os.path.join(self.internal_artifacts, "verification_report.json")
        CapabilityVerifier.save_report(report, report_path)

        # Sync artifacts
        self._save_artifacts(plan, env, report)

        print("=" * 60)
        if report.all_robust():
            print("[SUCCESS] All primitives verified robustly.")
            print("")
            print("  Technique hints (also in exploit.py comments):")
            from core.planner.technique_ir_gen import TechniqueIRGenerator
            for stage in plan.stages:
                hint = TechniqueIRGenerator.format_hint(
                    stage.technique_id, env.glibc_version,
                    ", ".join(stage.produces),
                )
                for line in hint.split("\n"):
                    print(f"  {line}")
        else:
            print("[WARNING] Some primitives not robust. See report.")
        print(f"[INFO] Exploit: {exploit_path}")
        print(f"[INFO] Report: {report_path}")
        print("=" * 60 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AutoPwn v4 — Capability-Driven Primitive Exploit Generation"
    )
    parser.add_argument("binary", help="Path to target binary")
    parser.add_argument("--mode", choices=["primitives", "full"], default="primitives",
                        help="Exploit mode: primitives (leaks only) or full (code exec)")
    parser.add_argument("--writeup-dir", default=None,
                        help="Directory containing CTF writeup .txt files for NLP analysis")
    parser.add_argument("--angr", action="store_true", default=False,
                        help="Use angr symbolic execution (default: DynamoRIO)")
    args = parser.parse_args()

    if not os.path.exists(args.binary):
        print(f"Error: Binary {args.binary} not found.")
        sys.exit(1)

    framework = AutoPwnFramework(
        args.binary,
        mode=args.mode,
        writeup_dir=args.writeup_dir,
    )
    framework.run()
