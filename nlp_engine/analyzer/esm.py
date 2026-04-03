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

        # Regex theo format của hook.c
        alloc_pattern = r"Alloc\s*\|\s*size\s*=\s*(\d+)\s*bytes\s*\|\s*address\s*=\s*(0x[0-9a-fA-F]+)"
        free_pattern = r"Free\s*\|.*?address\s*=\s*(0x[0-9a-fA-F]+)"
        alloc_match = re.search(alloc_pattern, line, re.IGNORECASE)
        free_match = re.search(free_pattern, line, re.IGNORECASE)
        
        if alloc_match:
            return {
                "type": "alloc", 
                "size": int(alloc_match.group(1)), 
                "addr": alloc_match.group(2)
            }
        if free_match:
            return {
                "type": "free", 
                "addr": free_match.group(1)
            }
        return None

    def generalize_address(self, addr):
        # Chuyển các addr thành các tên biến tự đặt có đánh số và để trong từ điển
        # Format tên: obj_0,... như tỏng paper
        if addr not in self.object_map:
            self.object_map[addr] = f"obj_{self.obj_counter}"
            self.obj_counter += 1
        return self.object_map[addr]

    def build_state_vector(self, current_action):
        # Xây dựng trạng thái bộ nhớ dựa trên các biến quan trọng.s
        state = {}
        for critical_var in self.critical_vars:
            # Đánh dấu là 'tracked' để chuẩn bị cho bước sau
            state[critical_var] = "tracked" 
        return state

    def process(self, log_file):
        print(f"[*] Bắt đầu xử lý file log: {log_file}")
        count = 0
        with open(log_file, "r") as f:
            for line in f:
                action = self.parse_log_line(line)
                
                # Bỏ qua dòng không phải Alloc/Free (ví dụ: các câu chào của đề bài)
                if not action:
                    continue
                # Tổng quát hóa
                action["label"] = self.generalize_address(action["addr"])
                # Tạo state vector
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
        print(f"[OK] Tri thức đã được đóng gói vào: {output_file}")

if __name__ == "__main__":
    # Các biến này sẽ lấy từ kết quả của Module 1
    critical_vars = []
    with open("./critical_vars.txt", "r") as f:
        critical_vars = ast.literal_eval(f.read())
    print(f"[*] Các biến nguy hiểm được tìm thấy gồm: {critical_vars}")
    analyzer = ESMAnalyzer(critical_vars)
    analyzer.process("./trace.log")
    analyzer.save_experience("experience_babyheap.json")