#!/usr/bin/env python3
"""
AutoPwn Benchmark Evaluation Framework

Evaluates generated exploit.py files against expected challenge criteria.
Focuses on:
1. Bug detection accuracy (critical)
2. Primitive correctness (critical)
3. Exploit chain validity (critical)
4. Address flexibility (user-adjustable)
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional


class ExploitEvaluator:
    """Evaluates a generated exploit.py against challenge expectations."""

    def __init__(self, challenge_config: dict, exploit_path: str, artifacts_dir: str):
        self.challenge = challenge_config
        self.exploit_path = exploit_path
        self.artifacts_dir = artifacts_dir
        self.exploit_content = ""
        self.exploit_lines = []

        if os.path.exists(exploit_path):
            with open(exploit_path, 'r') as f:
                self.exploit_content = f.read()
                self.exploit_lines = self.exploit_content.split('\n')

        self.artifacts = self._load_artifacts()

    def _load_artifacts(self) -> dict:
        """Load all intermediate artifacts for evaluation."""
        artifacts = {}
        artifact_files = [
            'critical_vars.json',
            'trace_events.json',
            'generalized_actions.json',
            'esm_output.json',
            'final_plan.json',
            'taint_results.json',
            'execution_results.json'
        ]

        for filename in artifact_files:
            path = os.path.join(self.artifacts_dir, filename)
            if os.path.exists(path):
                with open(path, 'r') as f:
                    try:
                        artifacts[filename] = json.load(f)
                    except json.JSONDecodeError:
                        artifacts[filename] = None

        return artifacts

    def evaluate_all(self) -> dict:
        """Run all evaluation metrics and return scores."""
        scores = {
            'challenge_id': self.challenge['id'],
            'bug_detection': self._evaluate_bug_detection(),
            'primitive_correctness': self._evaluate_primitive_correctness(),
            'exploit_chain': self._evaluate_exploit_chain(),
            'address_flexibility': self._evaluate_address_flexibility(),
        }

        scores['overall'] = self._calculate_overall(scores)
        return scores

    def _evaluate_bug_detection(self) -> dict:
        """Evaluate bug detection accuracy (weight: 0.30)."""
        expected_vulns = set(self.challenge.get('vulnerability_types', []))

        detected_vulns = self._detect_vulnerabilities_from_exploit()
        detected_vulns_artifact = self._detect_vulnerabilities_from_artifacts()

        all_detected = detected_vulns.union(detected_vulns_artifact)

        correct_vulnerability_type = bool(expected_vulns.intersection(all_detected))
        all_vulnerabilities_found = expected_vulns.issubset(all_detected)
        no_false_positives = len(all_detected - expected_vulns) == 0

        scores = {
            'correct_vulnerability_type': 1.0 if correct_vulnerability_type else 0.0,
            'all_vulnerabilities_found': 1.0 if all_vulnerabilities_found else 0.0,
            'no_false_positives': 1.0 if no_false_positives else 0.5,
        }

        weights = {
            'correct_vulnerability_type': 0.5,
            'all_vulnerabilities_found': 0.3,
            'no_false_positives': 0.2,
        }

        weighted_score = sum(scores[k] * weights[k] for k in scores)

        return {
            'scores': scores,
            'weighted_score': weighted_score,
            'expected': list(expected_vulns),
            'detected': list(all_detected),
            'details': {
                'from_exploit': list(detected_vulns),
                'from_artifacts': list(detected_vulns_artifact),
            }
        }

    def _evaluate_primitive_correctness(self) -> dict:
        """Evaluate primitive correctness (weight: 0.30)."""
        expected_primitives = set(self.challenge.get('expected_primitives', []))

        detected_primitives = self._detect_primitives_from_exploit()
        detected_primitives_artifact = self._detect_primitives_from_artifacts()

        all_detected = detected_primitives.union(detected_primitives_artifact)

        leak_primitive_valid = 'heap_leak' in all_detected or 'libc_leak' in all_detected
        write_primitive_valid = 'arbitrary_write' in all_detected or 'arbitrary_allocation' in all_detected
        primitive_chain_valid = self._check_primitive_chain(all_detected)

        scores = {
            'leak_primitive_valid': 1.0 if leak_primitive_valid else 0.0,
            'write_primitive_valid': 1.0 if write_primitive_valid else 0.0,
            'primitive_chain_valid': 1.0 if primitive_chain_valid else 0.5,
        }

        weights = {
            'leak_primitive_valid': 0.4,
            'write_primitive_valid': 0.4,
            'primitive_chain_valid': 0.2,
        }

        weighted_score = sum(scores[k] * weights[k] for k in scores)

        return {
            'scores': scores,
            'weighted_score': weighted_score,
            'expected': list(expected_primitives),
            'detected': list(all_detected),
            'details': {
                'from_exploit': list(detected_primitives),
                'from_artifacts': list(detected_primitives_artifact),
            }
        }

    def _evaluate_exploit_chain(self) -> dict:
        """Evaluate exploit chain validity (weight: 0.25)."""
        plan = self.artifacts.get('final_plan.json', {})
        esm = self.artifacts.get('esm_output.json', {})

        ir_stages = []
        if plan and 'ir' in plan:
            ir_stages = plan['ir']
        elif plan and 'stages' in plan:
            ir_stages = plan['stages']

        stage_order_correct = self._check_stage_order(ir_stages)
        transitions_valid = self._check_transitions(esm)
        technique_appropriate = self._check_technique_appropriateness(ir_stages)

        scores = {
            'stage_order_correct': 1.0 if stage_order_correct else 0.5,
            'transitions_valid': 1.0 if transitions_valid else 0.5,
            'technique_appropriate': 1.0 if technique_appropriate else 0.5,
        }

        weights = {
            'stage_order_correct': 0.3,
            'transitions_valid': 0.4,
            'technique_appropriate': 0.3,
        }

        weighted_score = sum(scores[k] * weights[k] for k in scores)

        return {
            'scores': scores,
            'weighted_score': weighted_score,
            'details': {
                'stage_count': len(ir_stages),
                'stages': [s.get('name', 'unknown') for s in ir_stages] if ir_stages else [],
            }
        }

    def _evaluate_address_flexibility(self) -> dict:
        """Evaluate address flexibility (weight: 0.15)."""
        user_adjustable_offsets = self._check_user_adjustable_offsets()
        clear_documentation = self._check_clear_documentation()
        modular_design = self._check_modular_design()

        scores = {
            'user_adjustable_offsets': 1.0 if user_adjustable_offsets else 0.5,
            'clear_documentation': 1.0 if clear_documentation else 0.0,
            'modular_design': 1.0 if modular_design else 0.5,
        }

        weights = {
            'user_adjustable_offsets': 0.4,
            'clear_documentation': 0.3,
            'modular_design': 0.3,
        }

        weighted_score = sum(scores[k] * weights[k] for k in scores)

        return {
            'scores': scores,
            'weighted_score': weighted_score,
            'details': {
                'config_variables_found': self._find_config_variables(),
                'comment_ratio': self._calculate_comment_ratio(),
            }
        }

    def _calculate_overall(self, scores: dict) -> dict:
        """Calculate overall score with weights."""
        weights = {
            'bug_detection': 0.30,
            'primitive_correctness': 0.30,
            'exploit_chain': 0.25,
            'address_flexibility': 0.15,
        }

        overall_score = sum(
            scores[category]['weighted_score'] * weights[category]
            for category in weights
        )

        grade = 'F'
        if overall_score >= 0.9:
            grade = 'A+'
        elif overall_score >= 0.8:
            grade = 'A'
        elif overall_score >= 0.7:
            grade = 'B+'
        elif overall_score >= 0.6:
            grade = 'B'
        elif overall_score >= 0.5:
            grade = 'C'
        elif overall_score >= 0.4:
            grade = 'D'

        return {
            'score': overall_score,
            'grade': grade,
            'weights': weights,
        }

    def _detect_vulnerabilities_from_exploit(self) -> set:
        """Detect vulnerability types mentioned in exploit.py."""
        vulns = set()
        content_lower = self.exploit_content.lower()

        vulnerability_patterns = {
            'uaf': ['use.after.free', 'uaf', 'dangling', 'freed.chunk', 'after.free'],
            'double_free': ['double.free', 'double_free', 'free.twice'],
            'heap_overflow': ['heap.overflow', 'overflow', 'chunk.overlap'],
            'off_by_one': ['off.by.one', 'null.byte.overflow', 'single.byte'],
            'tcache_poisoning': ['tcache.poison', 'tcache.dup', 'tcache.attack'],
            'index_confusion': ['index.confusion', 'index.mismatch'],
        }

        for vuln, patterns in vulnerability_patterns.items():
            for pattern in patterns:
                if pattern in content_lower:
                    vulns.add(vuln)
                    break

        return vulns

    def _detect_vulnerabilities_from_artifacts(self) -> set:
        """Detect vulnerability types from artifacts."""
        vulns = set()

        esm = self.artifacts.get('esm_output.json', {})
        if esm and 'bugs' in esm:
            for bug in esm['bugs']:
                if isinstance(bug, dict):
                    bug_type = bug.get('type', bug.get('name', ''))
                else:
                    bug_type = str(bug)

                if 'uaf' in bug_type.lower():
                    vulns.add('uaf')
                elif 'double' in bug_type.lower():
                    vulns.add('double_free')
                elif 'overflow' in bug_type.lower():
                    vulns.add('heap_overflow')
                elif 'off.by.one' in bug_type.lower():
                    vulns.add('off_by_one')
                elif 'tcache' in bug_type.lower():
                    vulns.add('tcache_poisoning')

        critical_vars = self.artifacts.get('critical_vars.json', {})
        if critical_vars and 'composite_taxonomy' in critical_vars:
            taxonomy = critical_vars['composite_taxonomy']
            if 'techniques' in taxonomy:
                for technique in taxonomy['techniques']:
                    if 'uaf' in technique.lower():
                        vulns.add('uaf')
                    elif 'double' in technique.lower():
                        vulns.add('double_free')
                    elif 'overflow' in technique.lower():
                        vulns.add('heap_overflow')

        return vulns

    def _detect_primitives_from_exploit(self) -> set:
        """Detect primitives used in exploit.py."""
        primitives = set()
        content_lower = self.exploit_content.lower()

        primitive_patterns = {
            'heap_leak': ['heap.base', 'heap.leak', 'heap_addr', 'heap_base'],
            'libc_leak': ['libc.base', 'libc.leak', 'libc.address', 'main_arena'],
            'stack_leak': ['stack.leak', 'stack_base', 'environ', 'stack_addr'],
            'arbitrary_write': ['arbitrary.write', 'write.what.where', 'tcache.poison'],
            'arbitrary_allocation': ['arbitrary.alloc', 'controlled.malloc'],
            'arbitrary_free': ['arbitrary.free', 'controlled.free'],
        }

        for prim, patterns in primitive_patterns.items():
            for pattern in patterns:
                if pattern in content_lower:
                    primitives.add(prim)
                    break

        return primitives

    def _detect_primitives_from_artifacts(self) -> set:
        """Detect primitives from artifacts."""
        primitives = set()

        esm = self.artifacts.get('esm_output.json', {})
        if esm and 'primitives' in esm:
            for prim in esm['primitives']:
                if isinstance(prim, dict):
                    prim_type = prim.get('type', prim.get('name', ''))
                else:
                    prim_type = str(prim)

                if 'leak' in prim_type.lower():
                    if 'heap' in prim_type.lower():
                        primitives.add('heap_leak')
                    elif 'libc' in prim_type.lower():
                        primitives.add('libc_leak')
                    elif 'stack' in prim_type.lower():
                        primitives.add('stack_leak')
                    else:
                        primitives.add('info_leak')
                elif 'write' in prim_type.lower():
                    primitives.add('arbitrary_write')
                elif 'alloc' in prim_type.lower():
                    primitives.add('arbitrary_allocation')
                elif 'free' in prim_type.lower():
                    primitives.add('arbitrary_free')

        return primitives

    def _check_primitive_chain(self, detected_primitives: set) -> bool:
        """Check if primitives are used in a valid chain."""
        plan = self.artifacts.get('final_plan.json', {})

        if not plan or 'ir' not in plan:
            return len(detected_primitives) >= 2

        ir_stages = plan['ir']
        has_leak = any('leak' in stage.get('name', '').lower() for stage in ir_stages)
        has_write = any('write' in stage.get('name', '').lower() or 'poison' in stage.get('name', '').lower() for stage in ir_stages)

        return has_leak and has_write

    def _check_stage_order(self, ir_stages: list) -> bool:
        """Check if exploit stages are in correct order."""
        if not ir_stages:
            return False

        stage_names = [stage.get('name', '').lower() for stage in ir_stages]

        expected_order = ['leak', 'write', 'alloc', 'rop']
        last_index = -1

        for expected in expected_order:
            for i, name in enumerate(stage_names):
                if expected in name and i > last_index:
                    last_index = i
                    break

        return last_index >= 0

    def _check_transitions(self, esm: dict) -> bool:
        """Check if state transitions are valid."""
        if not esm:
            return False

        if 'transitions' in esm:
            return len(esm['transitions']) > 0

        if 'states' in esm:
            return len(esm['states']) > 1

        return False

    def _check_technique_appropriateness(self, ir_stages: list) -> bool:
        """Check if chosen techniques match challenge requirements."""
        expected_techniques = set(self.challenge.get('expected_techniques', []))

        if not ir_stages:
            return False

        stage_names = ' '.join([stage.get('name', '').lower() for stage in ir_stages])

        matches = 0
        for technique in expected_techniques:
            if technique.lower() in stage_names:
                matches += 1

        return matches > 0

    def _check_user_adjustable_offsets(self) -> bool:
        """Check if exploit has user-adjustable offsets."""
        adjustable_patterns = [
            '# ADJUST:', '# CONFIG:', '# USER:', '# MODIFY:',
            'OFFSET', 'ADJUST_', 'CONFIG_', 'USER_OFFSET',
            'stack_leak - 0x', 'stack_leak -', 'environ'
        ]

        for line in self.exploit_lines:
            for pattern in adjustable_patterns:
                if pattern.lower() in line.lower():
                    return True

        return False

    def _check_clear_documentation(self) -> bool:
        """Check if exploit has clear documentation."""
        comment_ratio = self._calculate_comment_ratio()
        return comment_ratio >= 0.15

    def _check_modular_design(self) -> bool:
        """Check if exploit has modular design."""
        modular_patterns = [
            'def ', 'class ', 'function',
            'heap_base =', 'libc.address =', 'stack_leak =',
            'p64(', 'flat(['
        ]

        matches = 0
        for pattern in modular_patterns:
            if pattern in self.exploit_content:
                matches += 1

        return matches >= 3

    def _find_config_variables(self) -> list:
        """Find configuration variables in exploit."""
        config_vars = []
        config_patterns = [
            r'(\w+)\s*=\s*0x[0-9a-fA-F]+',
            r'(\w+)\s*=\s*[\d]+',
            r'#\s*(\w+)\s*:',
        ]

        for line in self.exploit_lines:
            for pattern in config_patterns:
                match = re.search(pattern, line)
                if match:
                    config_vars.append(match.group(1))

        return config_vars[:10]

    def _calculate_comment_ratio(self) -> float:
        """Calculate ratio of comment lines to total lines."""
        if not self.exploit_lines:
            return 0.0

        comment_lines = 0
        for line in self.exploit_lines:
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                comment_lines += 1

        return comment_lines / len(self.exploit_lines)


def evaluate_challenge(challenge_config: dict, results_dir: str) -> dict:
    """Evaluate a single challenge's generated exploit."""
    exploit_path = os.path.join(results_dir, 'exploit.py')
    artifacts_dir = results_dir

    if not os.path.exists(exploit_path):
        return {
            'challenge_id': challenge_config['id'],
            'error': 'exploit.py not found',
            'overall': {'score': 0.0, 'grade': 'F'}
        }

    evaluator = ExploitEvaluator(challenge_config, exploit_path, artifacts_dir)
    return evaluator.evaluate_all()


def print_evaluation_report(scores: dict):
    """Print a formatted evaluation report."""
    print("\n" + "=" * 60)
    print(f"  EVALUATION REPORT: {scores['challenge_id']}")
    print("=" * 60)

    categories = ['bug_detection', 'primitive_correctness', 'exploit_chain', 'address_flexibility']

    for category in categories:
        if category in scores:
            data = scores[category]
            score = data['weighted_score']
            print(f"\n  {category.replace('_', ' ').title()}")
            print(f"    Score: {score:.2f}")

            if 'scores' in data:
                for metric, value in data['scores'].items():
                    print(f"      {metric}: {value:.2f}")

            if 'expected' in data and 'detected' in data:
                print(f"      Expected: {data['expected']}")
                print(f"      Detected: {data['detected']}")

    print(f"\n  OVERALL")
    print(f"    Score: {scores['overall']['score']:.2f}")
    print(f"    Grade: {scores['overall']['grade']}")
    print("=" * 60 + "\n")


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: evaluate.py <challenges.json> <results_dir>")
        sys.exit(1)

    challenges_file = sys.argv[1]
    results_dir = sys.argv[2]

    with open(challenges_file, 'r') as f:
        config = json.load(f)

    challenge_id = os.path.basename(results_dir)
    challenge_config = None

    for c in config['challenges']:
        if c['id'] == challenge_id:
            challenge_config = c
            break

    if not challenge_config:
        print(f"Error: Challenge '{challenge_id}' not found in config")
        sys.exit(1)

    scores = evaluate_challenge(challenge_config, results_dir)
    print_evaluation_report(scores)

    output_file = os.path.join(results_dir, 'evaluation.json')
    with open(output_file, 'w') as f:
        json.dump(scores, f, indent=2)

    print(f"Evaluation saved to: {output_file}")
