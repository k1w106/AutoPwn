"""
Tier 1: Text-Based Interface Fuzzer.
Discovers heap interface by parsing stdout text via pwntools.
No DynamoRIO dependency. Pure heuristic + regex + canary oracle.
"""

import os
import re
import json
import time
import stat
from pathlib import Path
from pwn import process, context
context.log_level = 'error'


class InterfaceBlindException(Exception):
    pass


class TextInterfaceFuzzer:
    CANARY = b"CANARY_AAAA_CANARY"

    def __init__(self, binary_path: str, timeout: int = 15):
        self.binary_path = str(Path(binary_path).resolve())
        self.binary_name = os.path.basename(self.binary_path)
        self.binary_dir = os.path.dirname(self.binary_path)
        self.timeout = timeout
        self.menu_prompt = b"> "
        self.menu_text = ""
        self.candidates = []
        self.candidate_desc = {}
        self.roles = {}
        self.params = {}
        self.index_base = 0
        self.exec_cmd = [self.binary_path]
        self.env = {}
        self._view_output_format = "raw"
        self._prepare_environment()

    def _prepare_environment(self):
        libc_path = None
        ld_path = None
        try:
            for f in os.listdir(self.binary_dir):
                if re.match(r'libc\.so', f):
                    libc_path = os.path.join(self.binary_dir, f)
                elif re.match(r'ld-|ld\.linux', f):
                    ld_path = os.path.join(self.binary_dir, f)
        except PermissionError:
            pass
        if ld_path:
            try:
                st = os.stat(ld_path)
                os.chmod(ld_path, st.st_mode | stat.S_IEXEC)
            except OSError:
                pass
        try:
            st = os.stat(self.binary_path)
            if not (st.st_mode & stat.S_IEXEC):
                os.chmod(self.binary_path, st.st_mode | stat.S_IEXEC)
        except OSError:
            pass

        # Try direct first; if it produces output, use it
        try:
            p = process([self.binary_path])
            test = p.recv(timeout=0.5)
            p.close()
            if len(test) > 20 and b'invalid' not in test[:80].lower()[:80]:
                return
        except Exception:
            pass

        # Direct failed – fall back to custom ld/libc
        if ld_path and libc_path:
            self.exec_cmd = [ld_path, '--library-path', self.binary_dir, self.binary_path]
        elif libc_path:
            self.env['LD_PRELOAD'] = libc_path

    def _start_process(self):
        return process(self.exec_cmd, env=self.env or None)

    def _drain(self, p, timeout=0.3):
        try:
            return p.recv(timeout=timeout)
        except Exception:
            return b""

    # ── Phase 1: Menu Parsing ──────────────────────────────────────

    def _parse_menu(self):
        p = self._start_process()
        try:
            self.menu_text = p.recv(timeout=1.5)
        except Exception:
            self.menu_text = b""
        p.close()
        text = self.menu_text.decode(errors='replace')

        prompt_pats = [
            r'(?:[Ee]nter (?:your )?(?:choice|option|command|selection|action)[^:\n]*[:\s>?])',
            r'(?:[Yy]our (?:choice|option|command|selection|action)[^:\n]*[:\s>?])',
            r'(?:[Cc]hoice[:\s>?])',
            r'(?:[Cc]ommand[:\s>?])',
            r'(?:[Oo]ption[:\s>?])',
            r'(?:[Aa]ction[:\s>?])',
            r'(?:[Ss]elect[^:\n]*[:\s>?])',
            r'^\s*>>>\s*$',
            r'^\s*>>\s*$',
            r'^\s*>\s*$',
        ]
        for pat in prompt_pats:
            m = re.search(pat, text, re.MULTILINE)
            if m:
                raw = m.group(0)
                self.menu_prompt = raw.encode()
                if raw and raw[-1] in ('>', ':'):
                    self.menu_prompt = (raw.rstrip() + ' ').encode()
                break

        for line in text.split('\n'):
            ls = line.strip()
            m = re.match(r'^\s*(\d+|[a-zA-Z])\s*[\.\):\->\]]\s*(.+)$', ls)
            bracket = False
            if not m:
                m = re.match(r'^\s*\[(\d+|[a-zA-Z])\]\s*(.+)$', ls)
                bracket = True
            if m:
                ch = m.group(1)
                raw = m.group(2)
                raw = re.sub(r'^\s*[=\-]>?\s*', '', raw)
                desc = raw.strip()
                if bracket and ch.isalpha():
                    desc = (ch.lower() + desc).strip()
                if ch not in self.candidates:
                    self.candidates.append(ch)
                    self.candidate_desc[ch] = desc

        if not self.candidates:
            for c in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0']:
                if c.encode() in self.menu_text:
                    self.candidates.append(c)
            for c in ['M', 'F', 'S', 'E', 'A', 'R', 'Q', 'D', 'P', 'X']:
                pat = re.compile(r'(?:^|\n)\s*' + re.escape(c) + r'[\]:\)\.\->]')
                if pat.search(self.menu_text.decode(errors='replace')):
                    self.candidates.append(c)
        self.candidates = list(dict.fromkeys(self.candidates))

    def _is_menu_visible(self, out):
        t = out.decode(errors='replace').strip()
        if not t:
            return False
        mp = self.menu_prompt.decode(errors='replace').strip()
        if mp and mp in t:
            return True
        count = 0
        for c in self.candidates[:5]:
            pat = f'{c}.' in t or f'{c})' in t or f'{c} =>' in t
            if pat:
                count += 1
        return count >= 2

    def _is_sub_prompt(self, text):
        lines = [l.strip() for l in text.split('\n') if l.strip()]
        if not lines:
            return False
        mp = self.menu_prompt.decode(errors='replace').strip()
        for line in lines:
            if len(line) < 60 and (line.endswith('?') or line.endswith(':') or line.endswith('>')):
                if line != mp:
                    return True
        return False

    @staticmethod
    def _is_sub_prompt_line(line):
        line = line.strip() if isinstance(line, str) else line.decode(errors='replace').strip()
        if not line:
            return False
        if len(line) >= 60:
            return False
        ends = line.endswith('?') or line.endswith(':') or line.endswith('>')
        if not ends:
            return False
        stripped = line.rstrip('? :>').strip()
        if not stripped:
            return False
        return True

    # ── Phase 2: Find ALLOC ────────────────────────────────────────

    def _find_alloc(self):
        ERROR_KW = ['invalid', 'error', 'fail', 'wrong', 'illegal', 'unknown']
        for choice in self.candidates:
            p = self._start_process()
            self._drain(p, 0.4)
            try:
                p.sendline(choice.encode())
            except Exception:
                p.close()
                continue
            time.sleep(0.2)
            out = self._drain(p, 0.5)
            p.close()
            out_str = out.decode(errors='replace')
            has_sub = self._is_sub_prompt(out_str)
            has_error = any(kw in out_str.lower() for kw in ERROR_KW)
            if has_sub:
                self.roles[choice] = 'alloc'
                print(f"    '{choice}' → alloc (sub-prompt)")
                prompts = self._discover_params(choice)
                self.params[choice] = prompts
                return choice
            if not has_error:
                desc = self.candidate_desc.get(choice, '').lower()
                if any(kw in desc for kw in ['alloc', 'create', 'new', 'add', 'malloc']):
                    self.roles[choice] = 'alloc'
                    print(f"    '{choice}' → alloc (desc match)")
                    prompts = self._discover_params(choice)
                    self.params[choice] = prompts
                    return choice
        raise InterfaceBlindException("No ALLOC operation found")

    @staticmethod
    def _split_concatenated_prompts(line: str) -> list[str]:
        result = []
        buf = ""
        i = 0
        n = len(line)
        while i < n:
            ch = line[i]
            buf += ch
            if ch in ('?', ':', '>'):
                while i + 1 < n and line[i + 1] in (' ', '\t'):
                    i += 1
                    buf += line[i]
                stripped = buf.strip()
                if buf.endswith(' ') and stripped:
                    stripped += ' '
                result.append(stripped)
                buf = ""
            i += 1
        if buf.strip():
            result.append(buf.strip())
        return result

    def _discover_params(self, choice, alloc_choice=None):
        p = self._start_process()
        self._drain(p, 0.4)

        # Allocate a chunk first so non-alloc ops (edit/view/free) work
        if alloc_choice and choice != alloc_choice:
            alloc_steps = self.params.get(alloc_choice, [])
            if alloc_steps:
                try:
                    p.sendline(alloc_choice.encode())
                    time.sleep(0.1)
                    for pr in alloc_steps:
                        out = self._drain(p, 0.15)
                        dummy = self._dummy_for_prompt(pr.get('prompt_text', ''))
                        p.sendline(dummy)
                        time.sleep(0.1)
                    try:
                        p.recvuntil(self.menu_prompt, timeout=1)
                    except Exception:
                        pass
                except Exception:
                    pass

        try:
            p.sendline(choice.encode())
        except Exception:
            p.close()
            return []
        time.sleep(0.2)
        mp_stripped = self.menu_prompt.decode(errors='replace').strip()
        prompts = []
        for _ in range(10):
            try:
                out = p.recv(timeout=0.4)
            except Exception:
                break
            if not out:
                break
            if self._is_menu_visible(out):
                break
            out_text = out.decode(errors='replace')
            potential_prompts = []
            for line in out_text.split('\n'):
                line_s = line
                if not line.strip():
                    continue
                if not self._is_sub_prompt_line(line_s):
                    continue
                if mp_stripped in line_s or line_s == mp_stripped:
                    continue
                parts = self._split_concatenated_prompts(line_s)
                for part in parts:
                    if self._is_sub_prompt_line(part):
                        potential_prompts.append(part)
            matched = False
            for prompt_text in potential_prompts:
                matched = True
                clean = self._clean_prompt(prompt_text.encode())
                if prompts and prompts[-1]['prompt'] == clean:
                    continue
                prompts.append(dict(
                    prompt=clean,
                    prompt_text=clean.decode(errors='replace').strip(),
                    role='unknown',
                    type='bytes',
                ))
                dummy = self._dummy_for_prompt(prompt_text)
                try:
                    p.sendline(dummy)
                except Exception:
                    break
                time.sleep(0.15)
            if not matched:
                # Handle buffered prompts (e.g. edit data prompt hidden behind read())
                if out and len(out.strip()) < 8 and not self._is_menu_visible(out):
                    try:
                        p.sendline(b"dummy")
                        time.sleep(0.2)
                        out2 = p.recv(timeout=0.4)
                        if out2 and not self._is_menu_visible(out2):
                            out_text2 = out2.decode(errors='replace')
                            for line in out_text2.split('\n'):
                                line_s = line
                                if not line.strip(): continue
                                if not self._is_sub_prompt_line(line_s): continue
                                if mp_stripped in line_s or line_s == mp_stripped: continue
                                parts = self._split_concatenated_prompts(line_s)
                                for part in parts:
                                    if self._is_sub_prompt_line(part):
                                        potential_prompts.append(part)
                            for prompt_text in potential_prompts:
                                matched = True
                                clean = self._clean_prompt(prompt_text.encode())
                                if prompts and prompts[-1]['prompt'] == clean:
                                    continue
                                prompts.append(dict(
                                    prompt=clean,
                                    prompt_text=clean.decode(errors='replace').strip(),
                                    role='unknown',
                                    type='bytes',
                                ))
                                dummy = self._dummy_for_prompt(prompt_text)
                                try:
                                    p.sendline(dummy)
                                except Exception:
                                    break
                                time.sleep(0.15)
                    except Exception:
                        pass
                if not matched:
                    break
        p.close()
        self._assign_param_roles(choice, prompts)
        self._detect_multi_chunk_alloc(choice, prompts)
        return prompts

    @staticmethod
    def _clean_prompt(raw):
        s = raw.decode(errors='replace') if isinstance(raw, bytes) else raw
        s_stripped = s.strip()
        for sep in ['?', ':']:
            idx = s_stripped.find(sep)
            if idx >= 0:
                orig_idx = s.find(sep)
                if orig_idx >= 0 and orig_idx + 1 < len(s) and s[orig_idx + 1] == ' ':
                    return (s_stripped[:idx+1] + ' ').encode()
                return s_stripped[:idx+1].encode()
        if s.rstrip().endswith('>'):
            return s.rstrip().encode()
        return s_stripped.encode() if s else raw

    @staticmethod
    def _dummy_for_prompt(txt):
        t = txt.lower() if isinstance(txt, str) else txt.decode(errors='replace').lower()
        if any(kw in t for kw in ['size', 'len', 'count', 'amount']):
            return b"32"
        if any(kw in t for kw in ['index', 'idx', 'id', 'num']):
            return b"0"
        return b"AAAA"

    def _assign_param_roles(self, choice, prompts):
        for p in prompts:
            t = p['prompt_text'].lower()
            if any(kw in t for kw in ['index', 'idx', 'id', 'num']):
                p['role'] = 'idx'
                p['type'] = 'int'
            elif any(kw in t for kw in ['size', 'length', 'len', 'count', 'amount']):
                p['role'] = 'size'
                p['type'] = 'int'
            elif any(kw in t for kw in ['data', 'content', 'key', 'val', 'value', 'buf', 'flag', 'name', 'new']):
                p['role'] = 'data'
                p['type'] = 'bytes'

    # ── Phase 3: Oracle Check ──────────────────────────────────────

    def _alloc_chunk(self, p, choice, idx=0, size=0x30, data=None):
        if data is None:
            data = self.CANARY
        prompts = self.params.get(choice, [])
        try:
            p.sendline(choice.encode())
        except Exception:
            return
        time.sleep(0.1)
        for pr in prompts:
            try:
                out = p.recv(timeout=0.3)
            except Exception:
                break
            role = pr.get('role', 'unknown')
            try:
                if role == 'data':
                    p.sendline(data)
                else:
                    val = str(idx).encode() if role == 'idx' else str(size).encode()
                    p.sendline(val)
            except Exception:
                break
            time.sleep(0.15)

    def _check_role(self, candidate, alloc_choice):
        try:
            p = self._start_process()
        except Exception:
            return 'non-heap'
        self._drain(p, 0.4)
        self._alloc_chunk(p, alloc_choice, idx=0, size=0x30, data=self.CANARY)
        try:
            p.recvuntil(self.menu_prompt, timeout=1)
        except Exception:
            pass
        cand_prompts = self.params.get(candidate, [])
        role_by_prompt = self._guess_role_from_prompts(candidate, cand_prompts)
        try:
            p.sendline(candidate.encode())
        except Exception:
            p.close()
            return role_by_prompt
        time.sleep(0.1)
        out_before = b""
        for pr in cand_prompts:
            try:
                out = p.recv(timeout=0.3)
            except Exception:
                break
            out_before += out
            txt = out.decode(errors='replace').strip()
            if txt:
                try:
                    if pr.get('role') == 'data':
                        p.sendline(b"BBBB")
                    elif pr.get('role') == 'idx':
                        p.sendline(b"0")
                    elif pr.get('role') == 'size':
                        p.sendline(b"32")
                    else:
                        p.sendline(b"0")
                except Exception:
                    break
                time.sleep(0.15)
        try:
            out_after = p.recv(timeout=0.4)
        except Exception:
            out_after = b""
        all_out = out_before + out_after
        if self.CANARY in all_out or role_by_prompt == 'view':
            self._view_output_format = self._detect_view_output_format(all_out)
            p.close()
            return 'view'
        has_data_prompt = any(pr.get('role') == 'data' for pr in cand_prompts)
        if has_data_prompt:
            p.close()
            return 'edit'
        p.close()
        return role_by_prompt

    def _guess_role_from_prompts(self, choice, prompts):
        desc = self.candidate_desc.get(choice, '').lower()
        # "Get a ..." / "Create a ..." patterns are alloc (e.g., "Get a cat", "Get a dog")
        if 'get a ' in desc or 'create a ' in desc or 'make a ' in desc:
            return 'alloc'
        # Strong description match
        if any(kw in desc for kw in ['free', 'delete', 'remove', 'del', 'release', 'depart']):
            return 'free'
        if any(kw in desc for kw in ['view', 'show', 'read', 'dump', 'print', 'list', 'see']):
            if prompts:
                return 'view'
            return 'non-heap'
        if any(kw in desc for kw in ['edit', 'update', 'write', 'fill', 'change', 'modify', 'pet']):
            if prompts:
                return 'edit'
            return 'non-heap'
        if any(kw in desc for kw in ['alloc', 'create', 'new', 'add', 'malloc']):
            # Already handled by _find_alloc
            if prompts:
                return 'alloc'
            return 'non-heap'
        if any(kw in desc for kw in ['exit', 'quit', 'depart']):
            return 'non-heap'

        if not prompts:
            return 'non-heap'

        last = prompts[-1]['prompt_text'].lower()
        has_data = any(kw in last for kw in ['data', 'content', 'key', 'val', 'buf', 'flag', 'new'])
        if len(prompts) >= 2 and has_data:
            return 'edit'
        if len(prompts) == 1:
            first = prompts[0]['prompt_text'].lower()
            if 'size' in first:
                return 'non-heap'
            if 'index' in first or 'idx' in first:
                return 'view'
        return 'non-heap'

    @staticmethod
    def _detect_view_output_format(out: bytes) -> str:
        if b'key = ' in out or b'val = ' in out or b'value = ' in out:
            return "key_val"
        if b'Content:' in out or b'Data:' in out or b'data:' in out:
            return "prefixed"
        if b'says:' in out:
            return "prefixed"
        if b': ' in out:
            return "prefixed"
        return "raw"

    # ── Phase 4: Index Base ────────────────────────────────────────

    def _detect_index_base(self, alloc_choice):
        ERROR_KW = ['invalid', 'error', 'fail', 'wrong', 'out of bounds', 'illegal']
        prompts = self.params.get(alloc_choice, [])
        has_idx = any(p.get('role') == 'idx' for p in prompts)
        if not has_idx:
            self.index_base = 0
            return
        p = self._start_process()
        self._drain(p, 0.4)
        self._alloc_chunk(p, alloc_choice, idx=0, size=0x30, data=b"TEST")
        self._drain(p, 0.3)
        out = self._drain(p, 0.2)
        err_text = out.decode(errors='replace').lower()
        if not any(kw in err_text for kw in ERROR_KW):
            self.index_base = 0
        else:
            p.close()
            p = self._start_process()
            self._drain(p, 0.4)
            self._alloc_chunk(p, alloc_choice, idx=1, size=0x30, data=b"TEST")
            out = self._drain(p, 0.3)
            err_text = out.decode(errors='replace').lower()
            self.index_base = 1 if not any(kw in err_text for kw in ERROR_KW) else 0
        p.close()

    # ── Phase 5: Param Types ───────────────────────────────────────

    def _detect_param_types(self, choice):
        for p in self.params.get(choice, []):
            if p['type'] == 'unknown':
                p['type'] = 'int' if p['role'] in ('idx', 'size') else 'bytes'

    # ── Multi-chunk alloc detection ────────────────────────────────

    def _detect_multi_chunk_alloc(self, choice, prompts):
        """Detect if a single alloc creates multiple heap chunks (key+val store)."""
        data_count = sum(1 for p in prompts if p['role'] == 'data')
        size_count = sum(1 for p in prompts if p['role'] == 'size')
        self.multi_chunk_alloc = data_count > 1 or size_count > 1
        if self.multi_chunk_alloc:
            print(f"    [!] Detected multi-chunk alloc: {data_count} data, {size_count} size prompts")

    # ── Main Discovery ─────────────────────────────────────────────

    def discover(self):
        print("[*] Tier 1: Text-based interface discovery...")
        self._parse_menu()
        print(f"    Prompt: {self.menu_prompt}")
        print(f"    Candidates: {self.candidates}")
        for c in self.candidates:
            desc = self.candidate_desc.get(c, '')
            if desc:
                print(f"      {c}: {desc}")
        alloc_choice = self._find_alloc()
        self._alloc_choice = alloc_choice
        print(f"    Alloc params: {[p['role'] for p in self.params.get(alloc_choice, [])]}")
        for choice in self.candidates:
            if choice == alloc_choice or choice in self.roles:
                continue
            if choice not in self.params:
                prompts = self._discover_params(choice)
                self.params[choice] = prompts
            role = self._check_role(choice, alloc_choice)
            self.roles[choice] = role
            print(f"    '{choice}' → {role}")
        self._detect_index_base(alloc_choice)
        print(f"    Index base: {self.index_base}")
        for c in self.roles:
            self._detect_param_types(c)
        return self._build_interface_map()

    def _build_interface_map(self):
        ops = {}
        for choice, role in self.roles.items():
            if role in ('alloc', 'view', 'edit', 'free'):
                steps = []
                for p in self.params.get(choice, []):
                    steps.append(dict(
                        prompt=repr(p['prompt']),
                        type=p['type'],
                        arg=p['role'],
                    ))
                # Edit ops with only idx likely also have data (Content? etc)
                # May not appear if chunk was empty during discovery
                # Use empty prompt so synth sends data immediately (binary is in read())
                if role == 'edit' and len(steps) == 1 and steps[0]['arg'] == 'idx':
                    data_prompt = repr(b'')
                    steps.append(dict(
                        prompt=data_prompt,
                        type='bytes',
                        arg='data',
                    ))
                ops[choice] = dict(role=role, choice=choice, steps=steps)
        features = dict(
            index_base=self.index_base,
            letter_commands=any(c in 'MFSEARQ' for c in self.candidates),
            view_output_format=getattr(self, '_view_output_format', 'raw'),
            multi_chunk_alloc=getattr(self, 'multi_chunk_alloc', False),
        )
        return dict(
            menu_prompt=repr(self.menu_prompt),
            operations=ops,
            features=features,
        )


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True)
    parser.add_argument('--output', default=None)
    args = parser.parse_args()
    fuzzer = TextInterfaceFuzzer(args.target)
    result = fuzzer.discover()
    output = args.output or os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'artifacts', 'interface_map.json'
    )
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"\n[OK] Interface map saved to: {output}")
