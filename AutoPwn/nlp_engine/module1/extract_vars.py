import spacy
import sys
import os
import re
import json
import argparse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
CODE_TOKEN_RE = re.compile(
    r"(__\w+|0x[0-9a-fA-F]+|p(?:8|16|32|64)\([^)]*\)|b'[^']*')"
)
STOP_WORDS = {
    "the", "a", "an", "some", "any", "this", "that", "stuff",
    "we", "will", "need", "to", "and", "of", "it", "its",
}
PRONOUNS = {"we", "you", "it", "this", "that", "they", "i", "us", "he", "she"}

def preprocess(text: str) -> tuple[str, list[str]]:
    """
    Split raw writeup text into:
      - clean_text : prose with code tokens removed (for spaCy NLP)
      - code_tokens: raw code-like tokens extracted directly
    """
    code_tokens = CODE_TOKEN_RE.findall(text)
    clean_text = CODE_TOKEN_RE.sub(" ", text)
    return clean_text, code_tokens


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------
class NLPEngine:
    # ------------------------------------------------------------------
    # Static lookup tables
    # ------------------------------------------------------------------
    NORM_MAP: dict[str, str] = {
        "free hook":          "__free_hook",
        "malloc hook":        "__malloc_hook",
        "realloc hook":       "__realloc_hook",
        "libc base":          "libc_base",
        "heap base":          "heap_base",
        "heap address":       "heap_base",
        "stack base":         "stack_base",
        "stack address":      "stack_base",
        "safe linking":       "safe_linking",
        "pointer mangling":   "safe_linking",
        "xor key":            "xor_key",
        "system":             "system",
        "/bin/sh":            "/bin/sh",
        "bin sh":             "/bin/sh",
        "one gadget":         "one_gadget",
        "shell":              "shell",
        "rip":                "rip",
        "canary":             "stack_canary",
        "stack canary":       "stack_canary",
        "tcache":             "tcache",
        "unsorted bin":       "unsorted_bin",
        "fast bin":           "fastbin",
        "fastbin":            "fastbin",
        "small bin":          "smallbin",
        "large bin":          "largebin",
        "top chunk":          "top_chunk",
        "chunk":              "chunk",
        "main arena":         "main_arena",
        "environ":            "__environ",
        "envrion":            "__environ",
        "__envrion":          "__environ",
        "exit functions":     "__exit_functions",
        "__exit_functions":   "__exit_functions",
        "perthread struct":   "tcache_perthread_struct",
        "fd":                 "fd",
        "bk":                 "bk",
        "prev size":          "prev_size",
        "prev inuse":         "prev_inuse",
        "got":                "got",
        "plt":                "plt",
        "malloc":             "malloc",
        "free":               "free",
        "pop rdi":            "pop_rdi",
        "return address":     "return_address",
        "rtld global":        "_rtld_global",
        "link map":           "link_map",
        "tcache poisoning":   "tcache_poisoning",
        "chunk overlap":      "chunk_overlap",
        "unsortedbin leak":   "unsortedbin_leak",
        "arbitrary write":    "arbitrary_write",
        "libc leak":          "libc_leak",
        "stack leak":         "stack_leak",
        "control hijack":     "control_flow_hijack",
        "control flow":        "control_flow_hijack",
        "shell":              "shell",
        "get shell":          "shell",
        "spawn shell":        "shell",
        "uaf":                "uaf",
        "use after free":     "uaf",
        "double free":        "double_free",
        "overflow":           "overflow",
        "buffer overflow":    "overflow",
        "heap overflow":      "overflow",
        "oob read":           "oob_read",
        "oob write":          "oob_write",
    }
    TECHNICAL_KW: frozenset[str] = frozenset(NORM_MAP.keys())
    
    NORM_MAP: dict[str, str] = {
        "free hook":          "__free_hook",
        "malloc hook":        "__malloc_hook",
        "realloc hook":       "__realloc_hook",
        "libc base":          "libc_base",
        "heap base":          "heap_base",
        "heap address":       "heap_base",
        "stack base":         "stack_base",
        "stack address":      "stack_base",
        "safe linking":       "safe_linking",
        "pointer mangling":   "safe_linking",
        "xor key":            "xor_key",
        "system":             "system",
        "/bin/sh":            "/bin/sh",
        "bin sh":             "/bin/sh",
        "one gadget":         "one_gadget",
        "shell":              "shell",
        "rip":                "rip",
        "canary":             "stack_canary",
        "stack canary":       "stack_canary",
        "tcache":             "tcache",
        "unsorted bin":       "unsorted_bin",
        "fast bin":           "fastbin",
        "fastbin":            "fastbin",
        "small bin":          "smallbin",
        "large bin":          "largebin",
        "top chunk":          "top_chunk",
        "chunk":              "chunk",
        "main arena":         "main_arena",
        "environ":            "__environ",
        "envrion":            "__environ",
        "__envrion":          "__environ",
        "exit functions":     "__exit_functions",
        "__exit_functions":   "__exit_functions",
        "perthread struct":   "tcache_perthread_struct",
        "fd":                 "fd",
        "bk":                 "bk",
        "prev size":          "prev_size",
        "prev inuse":         "prev_inuse",
        "got":                "got",
        "plt":                "plt",
        "malloc":             "malloc",
        "free":               "free",
        "pop rdi":            "pop_rdi",
        "return address":     "return_address",
        "rtld global":        "_rtld_global",
        "link map":           "link_map",
        "tcache poisoning":   "tcache_poisoning",
        "chunk overlap":      "chunk_overlap",
        "unsortedbin leak":   "unsortedbin_leak",
        "arbitrary write":    "arbitrary_write",
        "arbitrary write primitive": "arbitrary_write",
        "arbitrary allocation": "arbitrary_allocation",
        "heap leak":          "heap_leak",
        "arbitrary free":     "arbitrary_free",
        "libc leak":          "libc_leak",
        "stack leak":         "stack_leak",
        "control hijack":     "control_flow_hijack",
        "control flow":        "control_flow_hijack",
        "shell":              "shell",
        "get shell":          "shell",
        "spawn shell":        "shell",
        "uaf":                "uaf",
        "use after free":     "uaf",
        "double free":        "double_free",
        "overflow":           "overflow",
        "buffer overflow":    "overflow",
        "heap overflow":      "overflow",
        "oob read":           "oob_read",
        "oob write":          "oob_write",
    }
    TECHNICAL_KW: frozenset[str] = frozenset(NORM_MAP.keys())
    
    CATEGORIES: dict[str, list[str]] = {
        "bugs":       ["uaf", "double_free", "overflow", "oob_read", "oob_write"],
        "primitives": ["arbitrary_allocation", "arbitrary_write", "heap_leak", "arbitrary_free"],
        "hooks":      ["__free_hook", "__malloc_hook", "__realloc_hook", "__exit_functions", "got", "plt", "_rtld_global"],
        "functions":  ["system", "one_gadget", "shell", "execve", "malloc", "free"],
        "leak_targets": ["__environ", "main_arena", "stack_canary", "xor_key", "link_map"],
        "leaks":      ["libc_base", "heap_base", "stack_base"],
        "structures": [
            "tcache", "unsorted_bin", "fastbin", "smallbin", "largebin",
            "chunk", "top_chunk", "tcache_perthread_struct"
        ],
        "metadata_fields": [
            "fd", "bk", "size", "prev_size", "prev_inuse"
        ],
        "techniques": [
            "tcache_poisoning", "chunk_overlap", "unsortedbin_leak", "safe_linking"
        ],
        "capabilities": [
            "libc_leak", "stack_leak", "control_flow_hijack"
        ],
        "gadgets":    ["pop_rdi", "return_address", "ret", "leave", "syscall"],
    }
    
    MALICIOUS_VERBS: frozenset[str] = frozenset({
        "overwrite", "corrupt", "modify", "hijack", "leak", "free", "allocate",
        "write", "read", "trigger", "poison", "forge", "exploit", "overflow",
        "redirect", "bypass"
    })

    HIGH_VALUE_TARGETS: frozenset[str] = frozenset({
        "__environ", "main_arena", "return_address", "fd", "bk", "__exit_functions",
        "libc_base", "heap_base", "stack_base", "stack_canary", "rip", "__free_hook", "__malloc_hook"
    })

    # ------------------------------------------------------------------
    def __init__(self):
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except OSError:
            print("[!] Lỗi: Chưa có model 'en_core_web_sm'.")
            print("[-] Cài đặt: python -m spacy download en_core_web_sm")
            sys.exit(1)
        
        # Build master ontology for validation
        self.ONTOLOGY_TERMS = set()
        for cat_terms in self.CATEGORIES.values():
            self.ONTOLOGY_TERMS.update(cat_terms)
    
    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    def _flatten(self, text: str) -> str:
        """Lower-case and collapse underscores/hyphens to spaces."""
        return re.sub(r"[_\-]+", " ", text.lower()).strip()

    def normalize(self, text: str) -> str | None:
        flat = self._flatten(text)
        # Direct match in map
        if flat in self.NORM_MAP:
            return self.NORM_MAP[flat]
        
        # Partial match
        for key, val in self.NORM_MAP.items():
            if key in flat:
                return val
        return None

    def is_technical(self, text: str) -> bool:
        flat = self._flatten(text)
        if any(kw in flat for kw in self.TECHNICAL_KW):
            return True
        # Check for technical-looking patterns
        if "_" in text or "0x" in text.lower():
            return True
        if re.search(r"\b(fd|bk|ptr|size|metadata|offset|struct|address)\b", flat):
            return True
        return False

    # ------------------------------------------------------------------
    # Extraction from prose (via spaCy)
    # ------------------------------------------------------------------

    def _extract_from_prose(self, text: str) -> set[str]:
        doc = self.nlp(text)
        found: set[str] = set()
        
        # 1. Noun Chunks
        for chunk in doc.noun_chunks:
            clean = " ".join(
                w for w in chunk.text.lower().split() if w not in STOP_WORDS
            )
            norm = self.normalize(clean)
            if norm:
                found.add(norm)
            elif self.is_technical(clean):
                found.add(clean)
        
        # 2. Multi-word technical terms (e.g., "use after free")
        # Some terms might not be caught as a single noun chunk
        lower_text = text.lower()
        for kw, norm in self.NORM_MAP.items():
            if kw in lower_text:
                found.add(norm)

        # 3. Verb-Object relations (enhanced)
        for token in doc:
            if token.pos_ == "VERB" and token.lemma_ in self.MALICIOUS_VERBS:
                for child in token.children:
                    if child.dep_ in ("dobj", "nsubjpass", "pobj"):
                        subtree_words = [
                            t.text for t in child.subtree
                            if t.pos_ in ("NOUN", "PROPN", "ADJ", "ADP", "NUM")
                        ]
                        phrase = " ".join(subtree_words)
                        if len(subtree_words) < 10 and self.is_technical(phrase):
                            norm = self.normalize(phrase)
                            found.add(norm if norm else phrase.lower())

        return found

    def _extract_states(self, text: str) -> list[dict]:
        """
        Extract relations that represent a state.
        e.g., "tcache size is 0x410" -> (tcache, size, 0x410)
        """
        doc = self.nlp(text)
        states = []
        
        # Weak relations that usually introduce noise unless the subject/object are high-value
        weak_verbs = {"be", "of", "contain", "store", "equal", "size", "hold", "set"}
        # Exploit transition/state change verbs
        strong_verbs = self.MALICIOUS_VERBS | {"become", "lead", "result", "point"}

        for token in doc:
            if token.lemma_ in strong_verbs or token.lemma_ in weak_verbs:
                subj = None
                objs = []
                
                # Check children for subject and objects
                for child in token.children:
                    if child.dep_ in ("nsubj", "nsubjpass"):
                        subj = child
                    if child.dep_ in ("attr", "dobj", "pobj", "acomp"):
                        objs.append(child)
                    # Handle prepositional objects (e.g., "overwrite X with Y")
                    if child.dep_ == "prep":
                        for grandchild in child.children:
                            if grandchild.dep_ == "pobj":
                                objs.append(grandchild)
                
                # If no subject found directly, check the head (for nested verbs like xcomp)
                if not subj and token.dep_ == "xcomp":
                    for child in token.head.children:
                        if child.dep_ in ("nsubj", "nsubjpass"):
                            subj = child
                
                if subj and objs:
                    s_text = " ".join([t.text for t in subj.subtree]).lower()
                    s_norm = self.normalize(s_text) or s_text

                    for obj in objs:
                        o_text = " ".join([t.text for t in obj.subtree]).lower()
                        o_norm = self.normalize(o_text) or o_text

                        if self._is_exploit_relevant(s_norm, token.lemma_, o_norm):
                            states.append({
                                "subject": s_norm,
                                "relation": token.lemma_,
                                "object": o_norm
                            })
            
            # Pattern: [Noun] "of" [Value] (e.g., "size of 0x30")
            if token.text.lower() == "of" and token.dep_ == "prep":
                parent = token.head
                child = None
                for c in token.children:
                    if c.dep_ == "pobj":
                        child = c
                
                if child:
                    p_norm = self.normalize(parent.text) or parent.text.lower()
                    c_text = child.text.lower()
                    if self._is_exploit_relevant(p_norm, "of", c_text):
                        states.append({
                            "subject": p_norm,
                            "relation": "of",
                            "object": c_text
                        })

        # Deduplicate states
        unique_states = []
        seen = set()
        for s in states:
            key = (s["subject"], s["relation"], s["object"])
            if key not in seen:
                unique_states.append(s)
                seen.add(key)
        
        return unique_states

    def _is_exploit_relevant(self, subj: str, relation: str, obj: str) -> bool:
        """Exploit-aware object validation: drop if object is garbage/non-ontology."""
        
        # 1. Aggressive pruning: Relation check
        if relation in ("be", "of") and obj in ("size", "bytes", "bits", "stuff", "process", "value"):
            return False
            
        # 2. Ontology validation: Object MUST be a known technical term or high-value target
        if obj not in self.ONTOLOGY_TERMS and obj not in self.HIGH_VALUE_TARGETS and "0x" not in obj:
            return False

        # 3. Malicious verbs are always strong indicators
        if relation in self.MALICIOUS_VERBS:
            return True
        
        # 4. State change implication
        if relation == "become" and ("corrupt" in obj or "poison" in obj):
            return True

        # 5. Weak relations allowed only if subject is also high-value
        if subj in self.ONTOLOGY_TERMS or subj in self.HIGH_VALUE_TARGETS:
            return True
            
        return False

    # ------------------------------------------------------------------
    # Inference Logic
    # ------------------------------------------------------------------

    def infer_knowledge(self, var_list: list[str], states: list[dict]) -> dict:
        """Infer high-level techniques, primitives, capabilities, and goals."""
        vars_set = set(var_list)
        
        # 1. Capability Inference
        capabilities = set()
        if "__environ" in vars_set or "stack_base" in vars_set:
            capabilities.add("stack_leak")
        if any(v in vars_set for v in ["libc_base", "main_arena", "__free_hook", "__malloc_hook", "unsortedbin_leak"]):
            capabilities.add("libc_leak")

        # 2. Primitive Detection
        primitives = set()
        has_overwrite = any(s["relation"] in ("overwrite", "modify", "corrupt", "poison") for s in states)
        
        if any(v in vars_set for v in ["tcache", "fastbin", "smallbin"]) and has_overwrite:
            primitives.add("arbitrary_allocation")
            
        if "arbitrary_allocation" in primitives and has_overwrite:
            # If we allocate into a hook/return address, it becomes arbitrary write
            if any(v in vars_set for v in ["return_address", "__free_hook", "__malloc_hook", "rip"]):
                primitives.add("arbitrary_write")

        if any(v in vars_set for v in ["heap_base", "chunk"]) and any(s["relation"] == "leak" for s in states):
            primitives.add("heap_leak")

        if "uaf" in vars_set or "double_free" in vars_set:
            primitives.add("arbitrary_free")
        
        # 3. Technique Detection (Rule-based)
        techniques = set()
        
        # tcache_poisoning: tcache + overwrite + fd
        has_tcache = "tcache" in vars_set or "tcache_perthread_struct" in vars_set
        has_fd = "fd" in vars_set
        if has_tcache and has_overwrite and has_fd:
            techniques.add("tcache_poisoning")
            
        # chunk_overlap: chunk + size + overwrite/modify
        has_chunk = "chunk" in vars_set
        has_size = "size" in vars_set or any(s["relation"] == "size" for s in states)
        if has_chunk and has_size and has_overwrite:
            techniques.add("chunk_overlap")

        if "unsorted_bin" in vars_set and any(s["relation"] == "leak" for s in states):
            techniques.add("unsortedbin_leak")

        # 4. Goal Detection
        goals = set()
        is_hijack_target = any(v in vars_set for v in ["return_address", "rip", "__free_hook", "__malloc_hook"])
        is_hijack_verb = any(s["relation"] == "hijack" or "control_flow_hijack" in s["object"] for s in states)
        if (is_hijack_target and has_overwrite) or is_hijack_verb:
            goals.add("control_flow_hijack")

        return {
            "techniques": sorted(list(techniques)),
            "primitives": sorted(list(primitives)),
            "capabilities": sorted(list(capabilities)),
            "goals": sorted(list(goals))
        }

    # ------------------------------------------------------------------
    # Extraction from inline code tokens
    # ------------------------------------------------------------------

    def _extract_from_code_tokens(self, tokens: list[str]) -> set[str]:
        found: set[str] = set()
        for tok in tokens:
            norm = self.normalize(tok)
            if norm:
                found.add(norm)
            elif self.is_technical(tok):
                found.add(tok.lower())
        return found

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_from_text(self, raw_text: str) -> tuple[list[str], list[dict]]:
        clean_text, code_tokens = preprocess(raw_text)

        vars_found = self._extract_from_prose(clean_text)
        vars_found |= self._extract_from_code_tokens(code_tokens)
        
        states_found = self._extract_states(clean_text)

        return sorted(vars_found), states_found

    def structure_output(self, var_list: list[str], states: list[dict]) -> dict:
        inferred = self.infer_knowledge(var_list, states)
        
        # 1. Basic Taxonomy (The Knowledge Inventory)
        taxonomy: dict[str, list] = {
            "bugs":            [],
            "primitives":      inferred["primitives"],
            "hooks":           [],
            "functions":       [],
            "leak_targets":    [],
            "capabilities":    inferred["capabilities"],
            "leaks":           [], # Misc/Legacy leaks
            "structures":      [],
            "metadata_fields": [],
            "techniques":      inferred["techniques"],
            "goals":           inferred["goals"],
            "gadgets":         [],
            "others":          [],
        }
        
        # Mapping found variables into taxonomy
        direct_taxonomy = {cat: [] for cat in self.CATEGORIES.keys()}
        
        for var in var_list:
            placed = False
            for cat, keywords in self.CATEGORIES.items():
                if var in keywords:
                    direct_taxonomy[cat].append(var)
                    placed = True
                    break
            if not placed:
                taxonomy["others"].append(var)

        # Merge inferred and direct findings
        for cat in taxonomy:
            if cat in direct_taxonomy:
                taxonomy[cat] = sorted(set(taxonomy[cat] + direct_taxonomy[cat]))
            if cat not in ("states", "others"):
                taxonomy[cat] = sorted(set(taxonomy[cat]))

        # 2. Exploit IR (The Semantic Layer)
        exploit_ir = {
            "bugs":       taxonomy["bugs"],
            "primitives": taxonomy["primitives"],
            "techniques": taxonomy["techniques"],
            "capabilities": taxonomy["capabilities"],
            "leak_targets": taxonomy["leak_targets"],
            "targets":    sorted(set(taxonomy["hooks"] + [v for v in var_list if v in self.HIGH_VALUE_TARGETS])),
            "goals":      taxonomy["goals"],
            "transitions": self.infer_transitions(taxonomy, states),
            "metadata": {
                "source": "nlp_writeup_extraction",
                "confidence_score": 0.85,
                "fusion_ready": True,
                "engine_version": "2.1-exploit-ir"
            }
        }

        return {
            "taxonomy": taxonomy,
            "exploit_ir": exploit_ir,
            "states": states
        }

    def infer_transitions(self, taxonomy: dict, states: list[dict]) -> list[dict]:
        """Infer CAUSE -> EFFECT transitions with primitive-layer accuracy."""
        transitions = []
        
        # Rule-based transition inference with primitive-layer accuracy
        
        # UAF -> arbitrary_free
        if "uaf" in taxonomy["bugs"] and "arbitrary_free" in taxonomy["primitives"]:
            transitions.append({"from": "uaf", "to": "arbitrary_free", "action": "trigger_uaf"})

        # arbitrary_free -> tcache_poisoning
        if "arbitrary_free" in taxonomy["primitives"] and "tcache_poisoning" in taxonomy["techniques"]:
            transitions.append({"from": "arbitrary_free", "to": "tcache_poisoning", "action": "poison_bin"})

        # tcache_poisoning -> arbitrary_allocation
        if "tcache_poisoning" in taxonomy["techniques"] and "arbitrary_allocation" in taxonomy["primitives"]:
            transitions.append({"from": "tcache_poisoning", "to": "arbitrary_allocation", "action": "malloc_at_target"})

        # arbitrary_allocation -> arbitrary_write
        if "arbitrary_allocation" in taxonomy["primitives"] and "arbitrary_write" in taxonomy["primitives"]:
            transitions.append({"from": "arbitrary_allocation", "to": "arbitrary_write", "action": "write_at_allocated_target"})

        # arbitrary_write -> control_flow_hijack
        if "arbitrary_write" in taxonomy["primitives"] and "control_flow_hijack" in taxonomy["goals"]:
             transitions.append({"from": "arbitrary_write", "to": "control_flow_hijack", "action": "overwrite_hook_or_ret"})

        # chunk_overlap -> heap_leak
        if "chunk_overlap" in taxonomy["techniques"] and "heap_leak" in taxonomy["primitives"]:
            transitions.append({"from": "chunk_overlap", "to": "heap_leak", "action": "read_oob"})

        # unsortedbin_leak -> libc_leak
        if "unsortedbin_leak" in taxonomy["techniques"] and "libc_leak" in taxonomy["capabilities"]:
            transitions.append({"from": "unsortedbin_leak", "to": "libc_leak", "action": "read_main_arena"})

        # libc_leak -> stack_leak
        if "libc_leak" in taxonomy["capabilities"] and "stack_leak" in taxonomy["capabilities"]:
            transitions.append({"from": "libc_leak", "to": "stack_leak", "action": "read_environ"})

        return transitions


# ---------------------------------------------------------------------------
# File-level helpers
# ---------------------------------------------------------------------------

def scan_file(path: str, engine: NLPEngine) -> tuple[list[str], list[dict]]:
    if not os.path.exists(path):
        print(f"[!] Không tìm thấy file: '{path}'")
        return [], []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return engine.extract_from_text(f.read())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Module 1 — NLP keyword and state extractor for CTF writeups"
    )
    parser.add_argument(
        "--writeup-dir",
        default="../data/writeups",
        help="Thư mục chứa các file writeup (.txt)",
    )
    parser.add_argument(
        "--output",
        default="../module3/critical_vars.json",
        help="Đường dẫn file JSON đầu ra",
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="(tuỳ chọn) Tên file cụ thể trong writeup-dir",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    engine = NLPEngine()
    all_vars: set[str] = set()
    all_states: list[dict] = []

    if args.file:
        target = os.path.join(args.writeup_dir, args.file)
        v, s = scan_file(target, engine)
        all_vars.update(v)
        all_states.extend(s)
    else:
        if not os.path.isdir(args.writeup_dir):
            print(f"[!] Thư mục không tồn tại: '{args.writeup_dir}'")
            sys.exit(1)
        for filename in sorted(os.listdir(args.writeup_dir)):
            if filename.endswith(".txt"):
                path = os.path.join(args.writeup_dir, filename)
                print(f"[*] Scanning: {filename}")
                v, s = scan_file(path, engine)
                all_vars.update(v)
                all_states.extend(s)

    # Deduplicate states across multiple files
    seen_states = set()
    unique_states = []
    for s in all_states:
        key = (s["subject"], s["relation"], s["object"])
        if key not in seen_states:
            unique_states.append(s)
            seen_states.add(key)

    structured = engine.structure_output(sorted(all_vars), unique_states)

    # Ensure output directory exists
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(structured, f, indent=4, ensure_ascii=False)

    print(f"[OK] Structured data saved → '{args.output}'")


if __name__ == "__main__":
    main()
