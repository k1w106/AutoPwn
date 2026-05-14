import re
import json
import os

class ESMAnalyzer:
    def __init__(self, critical_data):
        self.critical_data = critical_data
        self.object_map = {}  
        self.esm_states = []  
        self.obj_counter = 0
        self.libc_base = 0
        self.heap_base = 0
        self.stack_base = 0

    def parse_log_line(self, line):
        # Patterns
        libc_p  = r"LibcBase:\s*(0x[0-9a-fA-F]+)"
        heap_p  = r"HeapBase:\s*(0x[0-9a-fA-F]+)"
        stack_p = r"StackBase:\s*(0x[0-9a-fA-F]+)"
        alloc_p = r"Alloc.*?size\s*=\s*(\d+).*?address\s*=\s*(0x[0-9a-fA-F]+)"
        free_p  = r"Free\s*\|.*?address\s*=\s*(0x[0-9a-fA-F]+).*?next_ptr\s*=\s*(0x[0-9a-fA-F]+)"
        copy_p  = r"Copy\s*\|\s*size\s*=\s*(\d+).*?dest\s*=\s*(0x[0-9a-fA-F]+)\s*\|\s*source\s*=\s*(0x[0-9a-fA-F]+)\s*\|\s*type\s*=\s*(\w+)"
        leak_p  = r"Leak\s*\|.*?address\s*=\s*(0x[0-9a-fA-F]+).*?region\s*=\s*(\w+).*?type\s*=\s*(\w+)"

        if m := re.search(libc_p, line):
            self.libc_base = int(m.group(1), 16)
            return {"type": "internal", "key": "libc_base", "val": m.group(1)}
        if m := re.search(heap_p, line):
            self.heap_base = int(m.group(1), 16)
            return {"type": "internal", "key": "heap_base", "val": m.group(1)}
        if m := re.search(stack_p, line):
            self.stack_base = int(m.group(1), 16)
            return {"type": "internal", "key": "stack_base", "val": m.group(1)}
        
        if m := re.search(alloc_p, line):
            return {"type": "alloc", "size": int(m.group(1)), "addr": m.group(2).lower()}
        if m := re.search(free_p, line):
            return {"type": "free", "addr": m.group(1).lower(), "next_ptr": m.group(2).lower()}
        if m := re.search(copy_p, line):
            return {
                "type": "copy", 
                "size": int(m.group(1)), 
                "addr": m.group(2).lower(), 
                "source_addr": m.group(3).lower(),
                "func": m.group(4)
            }
        if m := re.search(leak_p, line):
            return {
                "type": "leak", 
                "addr": m.group(1).lower(), 
                "region": m.group(2),
                "func": m.group(3)
            }
            
        return None   

    def get_region(self, addr_int):
        if self.libc_base and abs(addr_int - self.libc_base) < 0x300000:
            return "libc"
        if self.heap_base and abs(addr_int - self.heap_base) < 0x200000:
            return "heap"
        if self.stack_base and abs(addr_int - self.stack_base) < 0x200000:
            return "stack"
        return "unknown"

    def generalize_address(self, addr):
        if not addr: return "none"
        if addr not in self.object_map:
            addr_int = int(addr, 16)
            region = self.get_region(addr_int)
            self.object_map[addr] = f"{region}_obj_{self.obj_counter}"
            self.obj_counter += 1
        return self.object_map[addr]

    def build_state_vector(self, action):
        if self.esm_states:
            state = json.loads(json.dumps(self.esm_states[-1]["state_after"]))
        else:
            state = {
                "hooks": {h: "unknown" for h in self.critical_data.get("hooks", [])},
                "leaks": {l: "unknown" for l in self.critical_data.get("leaks", [])},
                "functions": {f: "unknown" for f in self.critical_data.get("functions", [])},
                "primitives": {p: "unknown" for p in self.critical_data.get("primitives", [])}
            }

        if action["type"] == "internal":
            if action["key"] == "libc_base":
                if "libc_base" in state["leaks"]: state["leaks"]["libc_base"] = "base_identified"
            if action["key"] == "heap_base":
                if "heap_base" in state["leaks"]: state["leaks"]["heap_base"] = "base_identified"
            if action["key"] == "stack_base":
                if "stack_base" in state["leaks"]: state["leaks"]["stack_base"] = "base_identified"
        
        elif action["type"] == "leak":
            region = action["region"]
            for l in state["leaks"]:
                if region in l: state["leaks"][l] = f"leaked_via_{action['func']}"
            if region == "heap" and "xor_key" in state["leaks"]:
                state["leaks"]["xor_key"] = "potentially_leaked"
                if "safe_linking" in state["primitives"]:
                    state["primitives"]["safe_linking"] = "active_detected"
        
        elif action["type"] == "free":
            if "next_ptr" in action and int(action["next_ptr"], 16) != 0:
                if "safe_linking" in state["primitives"]:
                    state["primitives"]["safe_linking"] = "visible_in_trace"

        elif action["type"] == "copy":
            dest_int = int(action["addr"], 16)
            dest_region = self.get_region(dest_int)
            if dest_region == "libc":
                for h in state["hooks"]:
                    state["hooks"][h] = f"overwritten_via_{action['func']}"
            elif dest_region == "stack":
                state["functions"]["shell"] = "rip_hijack_attempted"

        return state

    def process(self, log_file):
        print(f"[*] Bắt đầu phân tích ESM từ: {log_file}")
        if not os.path.exists(log_file):
            print(f"[!] Không tìm thấy file log.")
            return

        with open(log_file, "r") as f:
            for line in f:
                action = self.parse_log_line(line)
                if not action: continue
                
                if "addr" in action:
                    action["name"] = self.generalize_address(action["addr"])
                
                current_state = self.build_state_vector(action)
                
                self.esm_states.append({
                    "step": len(self.esm_states) + 1,
                    "action": action,
                    "state_after": current_state
                })

    def save_experience(self, output_file):
        with open(output_file, "w") as f:
            json.dump(self.esm_states, f, indent=4)
        print(f"[COMPLETE] ESM Analysis saved to: {output_file}")

if __name__ == "__main__":
    critical_file = "./critical_vars.json"
    if os.path.exists(critical_file):
        with open(critical_file, "r") as f:
            critical_data = json.load(f)
    else:
        critical_data = {}
        
    analyzer = ESMAnalyzer(critical_data)
    analyzer.process("./trace.log")
    analyzer.save_experience("data_flow.json")
