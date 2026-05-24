"""
How2Heap Parser — reads 144 C source files from data/how2heap_sources/
and extracts structured metadata: technique name, glibc version range,
required bugs, heap operations sequence, and fake chunk layout hints.
"""

import os
import re
import json
from typing import Dict, List, Optional, Any

CACHE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "parsed_techniques.json"
)

HOW2HEAP_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "how2heap_sources"
)


def parse_glibc_version_from_dirname(dirname: str) -> Optional[str]:
    m = re.match(r"glibc_([0-9]+\.[0-9]+)", dirname)
    if m:
        return m.group(1)
    return None


def extract_technique_name(filename: str) -> str:
    return filename.replace(".c", "")


def extract_description(content: str) -> str:
    m = re.search(
        r'(?:This file demonstrates|This is a|The following)[^.]*\.',
        content,
        re.IGNORECASE
    )
    if m:
        return m.group(0).strip()
    m = re.search(r'printf\("([^"]{10,200})"\)', content)
    if m:
        return m.group(1).strip()
    return ""


def extract_glibc_version_mention(content: str) -> Optional[str]:
    m = re.search(r'tested\s+(?:on|against|with)\s+glibc\s+([0-9]+\.[0-9]+)', content, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r'glibc\s+([0-9]+\.[0-9]+)', content, re.IGNORECASE)
    if m:
        return m.group(1)
    return None


def extract_bug_types(content: str) -> List[str]:
    bugs = []
    text_lower = content.lower()

    if "vulnerability" in text_lower or "uaf" in text_lower or "use after free" in text_lower:
        bugs.append("uaf")
    if "double free" in text_lower or "double-free" in text_lower:
        bugs.append("double_free")
    if "overflow" in text_lower or "buffer overflow" in text_lower or "heap overflow" in text_lower:
        bugs.append("overflow")
    if "off by one" in text_lower or "off-by-one" in text_lower:
        bugs.append("off_by_one")
    if "arbitrary free" in text_lower:
        bugs.append("arbitrary_free")
    if "null byte" in text_lower:
        bugs.append("null_byte")

    if not bugs:
        if "overwrite" in text_lower:
            bugs.append("uaf")
        elif "poison" in text_lower:
            bugs.append("uaf")
        else:
            bugs.append("uaf")

    return bugs


def extract_heap_operations(content: str) -> List[Dict[str, Any]]:
    operations = []
    lines = content.split('\n')
    for line in lines:
        stripped = line.strip()
        m_alloc = re.match(r'.*\b(\w+\s*)\s*=\s*malloc\((\d+)\)', stripped)
        if m_alloc and 'int' in line:
            name = m_alloc.group(1).strip().rstrip('*')
            size = int(m_alloc.group(2))
            operations.append({
                "op": "ALLOC", "var": name, "size": size,
                "line": stripped[:80]
            })
            continue
        m_free = re.match(r'.*\bfree\((\w+)\)', stripped)
        if m_free:
            name = m_free.group(1)
            if name not in ('stdin', 'stdout', 'stderr', 'buf'):
                operations.append({
                    "op": "FREE", "var": name,
                    "line": stripped[:80]
                })
            continue
        m_write = re.match(r'.*(\w+)\[.*\]\s*=\s*\(?\(?\w+\)?\s*\(?\s*\(?\(?\(?\s*(\w+)', stripped)
        if m_write and 'VULNERABILITY' in content.upper():
            var = m_write.group(1)
            val = m_write.group(2)
            operations.append({
                "op": "OVERWRITE",
                "target_var": var,
                "source_var": val,
                "line": stripped[:80]
            })

    return operations


def parse_single_file(filepath: str, glibc_version: str) -> Optional[Dict[str, Any]]:
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
    except Exception:
        return None

    filename = os.path.basename(filepath)
    tech_id = extract_technique_name(filename)

    description = extract_description(content)
    version_mention = extract_glibc_version_mention(content)

    min_ver = glibc_version
    max_ver = glibc_version
    if version_mention:
        try:
            parts = version_mention.split('.')
            if len(parts) >= 2:
                v = float(f"{parts[0]}.{parts[1]}")
                if v < float(glibc_version):
                    min_ver = version_mention
        except ValueError:
            pass

    bugs = extract_bug_types(content)
    operations = extract_heap_operations(content)

    return {
        "id": tech_id,
        "source_file": filepath,
        "glibc_dir_version": glibc_version,
        "description": description or f"{tech_id} technique",
        "glibc_versions": {"min": min_ver, "max": max_ver},
        "bug_types": bugs,
        "heap_operations": operations,
    }


def parse_all(how2heap_dir: str = None, force: bool = False) -> Dict[str, Any]:
    if how2heap_dir is None:
        how2heap_dir = HOW2HEAP_DIR

    cache_path = CACHE_FILE
    if os.path.exists(cache_path) and not force:
        try:
            with open(cache_path, 'r') as f:
                return json.load(f)
        except Exception:
            pass

    if not os.path.isdir(how2heap_dir):
        return {"techniques": []}

    all_techniques = []
    for entry in sorted(os.listdir(how2heap_dir)):
        version_dir = os.path.join(how2heap_dir, entry)
        if not os.path.isdir(version_dir):
            continue
        glibc_ver = parse_glibc_version_from_dirname(entry)
        if not glibc_ver:
            continue

        for filename in sorted(os.listdir(version_dir)):
            if not filename.endswith('.c'):
                continue
            filepath = os.path.join(version_dir, filename)
            parsed = parse_single_file(filepath, glibc_ver)
            if parsed:
                all_techniques.append(parsed)

    result = {
        "version": "1.0",
        "description": "Parsed techniques from how2heap C sources",
        "techniques": all_techniques
    }

    try:
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, 'w') as f:
            json.dump(result, f, indent=2)
    except Exception:
        pass

    return result


def get_parsed_techniques(force_reparse: bool = False) -> Dict[str, Any]:
    return parse_all(force=force_reparse)


def technique_id_to_filename(tech_id: str) -> str:
    return f"{tech_id}.c"


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="Force re-parse")
    args = parser.parse_args()

    result = parse_all(force=args.force)
    print(f"Parsed {len(result['techniques'])} technique entries")
    for t in result['techniques']:
        print(f"  {t['id']:<35} glibc {t['glibc_dir_version']:<6} bugs={t['bug_types']}")
    print(f"\nCache saved to {CACHE_FILE}")
