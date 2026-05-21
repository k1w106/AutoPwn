#!/usr/bin/env python3
"""
AutoPwn Benchmark Runner

Runs the autopwn framework on each challenge in benchmarks/ and evaluates
the generated exploits.

Usage:
    python run_benchmark.py [--challenge <id>] [--all] [--skip-missing]
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


class BenchmarkRunner:
    """Runs benchmarks and collects results."""

    def __init__(self, root_dir: str, challenges_file: str):
        self.root_dir = os.path.abspath(root_dir)
        self.benchmarks_dir = os.path.join(self.root_dir, 'benchmarks')
        self.results_dir = os.path.join(self.benchmarks_dir, 'results')
        self.outputs_dir = os.path.join(self.root_dir, 'outputs')
        self.artifacts_dir = os.path.join(self.root_dir, 'core', 'artifacts')

        os.makedirs(self.results_dir, exist_ok=True)

        with open(challenges_file, 'r') as f:
            self.config = json.load(f)

    def get_challenge_dir(self, challenge_id: str) -> str:
        """Get the directory path for a challenge."""
        return os.path.join(self.benchmarks_dir, challenge_id)

    def get_result_dir(self, challenge_id: str) -> str:
        """Get the result directory path for a challenge."""
        return os.path.join(self.results_dir, challenge_id)

    def challenge_exists(self, challenge_id: str) -> bool:
        """Check if a challenge directory exists and has required files."""
        challenge_dir = self.get_challenge_dir(challenge_id)
        if not os.path.exists(challenge_dir):
            return False

        binary_path = os.path.join(challenge_dir, 'binary')
        return os.path.exists(binary_path)

    def run_autopwn(self, challenge_id: str, use_angr: bool = False) -> bool:
        """Run autopwn on a challenge."""
        challenge_dir = self.get_challenge_dir(challenge_id)
        binary_path = os.path.join(challenge_dir, 'binary')

        if not os.path.exists(binary_path):
            print(f"  [SKIP] Binary not found: {binary_path}")
            return False

        print(f"  [RUN] Running autopwn on {challenge_id}...")

        autopwn_script = os.path.join(self.root_dir, 'autopwn.py')
        angr_flag = '--angr' if use_angr else ''

        cmd = f"{sys.executable} {autopwn_script} {binary_path} {angr_flag}"

        start_time = time.time()
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=600,
                cwd=self.root_dir
            )

            elapsed = time.time() - start_time
            print(f"  [DONE] autopwn completed in {elapsed:.2f}s")

            if result.returncode != 0:
                print(f"  [WARN] autopwn exited with code {result.returncode}")
                if result.stderr:
                    print(f"  [STDERR] {result.stderr[:500]}")

            return True

        except subprocess.TimeoutExpired:
            print(f"  [ERROR] autopwn timed out after 600s")
            return False
        except Exception as e:
            print(f"  [ERROR] autopwn failed: {e}")
            return False

    def copy_results(self, challenge_id: str) -> str:
        """Copy generated exploit and artifacts to results directory."""
        result_dir = self.get_result_dir(challenge_id)
        os.makedirs(result_dir, exist_ok=True)

        exploit_path = os.path.join(self.outputs_dir, 'exploits', 'exploit.py')
        if os.path.exists(exploit_path):
            shutil.copy(exploit_path, result_dir)
            print(f"  [COPY] exploit.py -> {result_dir}")

        for filename in [
            'critical_vars.json',
            'trace_events.json',
            'generalized_actions.json',
            'esm_output.json',
            'final_plan.json',
            'taint_results.json',
            'execution_results.json'
        ]:
            src = os.path.join(self.artifacts_dir, filename)
            if os.path.exists(src):
                shutil.copy(src, result_dir)

        return result_dir

    def evaluate(self, challenge_id: str) -> dict:
        """Evaluate the generated exploit for a challenge."""
        result_dir = self.get_result_dir(challenge_id)
        evaluate_script = os.path.join(self.benchmarks_dir, 'scripts', 'evaluate.py')
        challenges_file = os.path.join(self.benchmarks_dir, 'challenges.json')

        cmd = f"{sys.executable} {evaluate_script} {challenges_file} {result_dir}"

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60
            )

            evaluation_file = os.path.join(result_dir, 'evaluation.json')
            if os.path.exists(evaluation_file):
                with open(evaluation_file, 'r') as f:
                    return json.load(f)
            else:
                return {'error': 'evaluation.json not created'}

        except Exception as e:
            return {'error': str(e)}

    def run_single(self, challenge_id: str, use_angr: bool = False) -> dict:
        """Run a single benchmark."""
        print(f"\n{'='*60}")
        print(f"  BENCHMARK: {challenge_id}")
        print(f"{'='*60}")

        if not self.challenge_exists(challenge_id):
            return {
                'challenge_id': challenge_id,
                'status': 'skipped',
                'reason': 'challenge directory or binary not found'
            }

        success = self.run_autopwn(challenge_id, use_angr)
        if not success:
            return {
                'challenge_id': challenge_id,
                'status': 'failed',
                'reason': 'autopwn execution failed'
            }

        result_dir = self.copy_results(challenge_id)
        evaluation = self.evaluate(challenge_id)

        return {
            'challenge_id': challenge_id,
            'status': 'completed',
            'result_dir': result_dir,
            'evaluation': evaluation
        }

    def run_all(self, use_angr: bool = False, skip_missing: bool = False) -> list:
        """Run all benchmarks."""
        results = []

        for challenge in self.config['challenges']:
            challenge_id = challenge['id']

            if skip_missing and not self.challenge_exists(challenge_id):
                print(f"\n  [SKIP] {challenge_id} (no binary)")
                results.append({
                    'challenge_id': challenge_id,
                    'status': 'skipped',
                    'reason': 'challenge directory or binary not found'
                })
                continue

            result = self.run_single(challenge_id, use_angr)
            results.append(result)

        return results

    def print_summary(self, results: list):
        """Print benchmark summary."""
        print(f"\n{'='*60}")
        print(f"  BENCHMARK SUMMARY")
        print(f"{'='*60}")

        total = len(results)
        completed = sum(1 for r in results if r.get('status') == 'completed')
        failed = sum(1 for r in results if r.get('status') == 'failed')
        skipped = sum(1 for r in results if r.get('status') == 'skipped')

        print(f"\n  Total: {total}")
        print(f"  Completed: {completed}")
        print(f"  Failed: {failed}")
        print(f"  Skipped: {skipped}")

        print(f"\n  {'Challenge':<35} {'Status':<10} {'Score':<8} {'Grade':<6}")
        print(f"  {'-'*35} {'-'*10} {'-'*8} {'-'*6}")

        for r in results:
            challenge_id = r['challenge_id']
            status = r.get('status', 'unknown')

            if status == 'completed' and 'evaluation' in r:
                eval_data = r['evaluation']
                if 'overall' in eval_data:
                    score = f"{eval_data['overall']['score']:.2f}"
                    grade = eval_data['overall']['grade']
                else:
                    score = 'N/A'
                    grade = 'N/A'
            else:
                score = 'N/A'
                grade = 'N/A'

            print(f"  {challenge_id:<35} {status:<10} {score:<8} {grade:<6}")

        print(f"\n{'='*60}\n")

    def save_summary(self, results: list, output_file: str):
        """Save benchmark summary to file."""
        summary = {
            'timestamp': datetime.now().isoformat(),
            'total': len(results),
            'completed': sum(1 for r in results if r.get('status') == 'completed'),
            'failed': sum(1 for r in results if r.get('status') == 'failed'),
            'skipped': sum(1 for r in results if r.get('status') == 'skipped'),
            'results': results
        }

        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"Summary saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(description='AutoPwn Benchmark Runner')
    parser.add_argument('--challenge', type=str, help='Run a specific challenge')
    parser.add_argument('--all', action='store_true', help='Run all challenges')
    parser.add_argument('--angr', action='store_true', help='Use angr instead of DynamoRIO')
    parser.add_argument('--skip-missing', action='store_true', help='Skip challenges without binaries')
    parser.add_argument('--root', type=str, default='..', help='Root directory of autopwn project')

    args = parser.parse_args()

    root_dir = os.path.abspath(args.root)
    challenges_file = os.path.join(root_dir, 'benchmarks', 'challenges.json')

    if not os.path.exists(challenges_file):
        print(f"Error: challenges.json not found at {challenges_file}")
        sys.exit(1)

    runner = BenchmarkRunner(root_dir, challenges_file)

    if args.challenge:
        result = runner.run_single(args.challenge, args.angr)
        runner.print_summary([result])
        runner.save_summary([result], os.path.join(runner.results_dir, 'summary.json'))
    elif args.all:
        results = runner.run_all(args.angr, args.skip_missing)
        runner.print_summary(results)
        runner.save_summary(results, os.path.join(runner.results_dir, 'summary.json'))
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
