import re
import json
import ast 

class ESMAnalyzer:
    def __init__(self, critical_vars):
        self.critical_vars = critical_vars
        self.object_map = {}  
        self.esm_states = []  
        self.obj_counter = 0

    def parse_log_line(self, line):
        alloc_p = r"Alloc.*?size\s*=\s*(\d+).*?address\s*=\s*(0x[0-9a-fA-F]+)"
        free_p  = r"Free\s*\|.*?address\s*=\s*(0x[0-9a-fA-F]+)"
        copy_p  = r"Copy\s*\|\s*size\s*=\s*(\d+)\s*bytes\s*\|\s*dest\s*=\s*(0x[0-9a-fA-F]+)\s*\|\s*source\s*=\s*(0x[0-9a-fA-F]+)\s*\|\s*type\s*=\s*(\w+)"
        leak_p  = r"Leak\s*\|\s*size\s*=\s*(\d+).*?address\s*=\s*(0x[0-9a-fA-F]+).*?type\s*=\s*(\w+)"

        if m := re.search(alloc_p, line, re.IGNORECASE):
            return {"type": "alloc", "size": int(m.group(1)), "addr": m.group(2).lower()}
        if m := re.search(free_p, line, re.IGNORECASE):
            return {"type": "free", "addr": m.group(1).lower()}
        if m := re.search(copy_p, line, re.IGNORECASE):
            return {
                "type": "copy", 
                "size": int(m.group(1)), 
                "addr": m.group(2).lower(),  # PHẢI LÀ 'addr' ĐỂ KHÔNG BỊ KEYERROR
                "source_addr": m.group(3).lower(),
                "func": m.group(4)
            }
        if m := re.search(leak_p, line, re.IGNORECASE):
            return {
                "type": "leak", 
                "size": int(m.group(1)), 
                "addr": m.group(2).lower(), 
                "func": m.group(3)
            }
            
        return None   

    def generalize_address(self, addr):
        if addr not in self.object_map:
            self.object_map[addr] = f"obj_{self.obj_counter}"
            self.obj_counter += 1
        return self.object_map[addr]

    def build_state_vector(self, action):
        state = {}
        for var in self.critical_vars:
            # Logic cập nhật trạng thái ESM dựa trên hành động
            if action["type"] == "copy":
                state[var] = f"potentially_modified_by_{action['name']}"
            elif action["type"] == "leak":
                state[var] = f"potentially_leaked_via_{action['name']}"
            elif action["type"] == "free":
                state[var] = "tracked_after_free"
            else:
                state[var] = "tracked"
        return state

    def process(self, log_file):
        print(f"[*] Bắt đầu xử lý file log: {log_file}")
        count = 0
        with open(log_file, "r") as f:
            for line in f:
                action = self.parse_log_line(line)
                if not action:
                    continue
                action["name"] = self.generalize_address(action["addr"])
                

                current_state = self.build_state_vector(action)
                
                self.esm_states.append({
                    "step": len(self.esm_states) + 1,
                    "action": action,
                    "state_after": current_state
                })
                count += 1
        print(f"[+] Hoàn tất. Đã ghi nhận {count} thao tác heap.")

    def save_experience(self, output_file):
        with open(output_file, "w") as f:
            json.dump(self.esm_states, f, indent=4)
        print(f"[COMPLETE] Tri thức đã được đóng gói vào: {output_file}")

if __name__ == "__main__":
    with open("./critical_vars.txt", "r") as f:
        critical_vars = ast.literal_eval(f.read())
        
    analyzer = ESMAnalyzer(critical_vars)
    analyzer.process("./trace.log")
    analyzer.save_experience("data_flow.json")