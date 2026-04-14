import spacy
import sys
import os

class NLPEngine:
    def __init__(self):
        # Load model NLP để phân tích cú pháp
        try:
        # en: Tiếng Anh
        # sm (Small): tiết kiệm tài nguyên
        # core: dùng để phân tích ngữ pháp
            self.nlp = spacy.load("en_core_web_sm")
        except OSError:
            print("[!] Lỗi: Chưa có model 'en_core_web_sm'.")
            print("[-] Install en_core_web_sm: python -m spacy download en_core_web_sm")
            sys.exit(1)
        
        # Danh sách các động từ độc hại ban đầu (trích từ paper)
        self.malicious_verbs = {"overwrite", "corrupt", "modify", 
                                "hijack", "leak", "control"
                                }
        self.technical_keywords = {
            'hook', 'free_hook', 'malloc_hook', 'realloc_hook', 
            'base', 'libc', 'heap', 'stack', 'address', 'addr',
            'pointer', 'ptr', 'chunk', 'top_chunk', 'unsorted', 'tcache',
            'system', 'bin_sh', 'rip', 'eip', 'pc', 'canary', 'fd', 'bk'
        }
    def is_technical(self, text):
        text_lower = text.lower()
        return any(kw in text_lower for kw in self.technical_keywords)

    def extract_from_text(self, text):
        doc = self.nlp(text)
        critical_vars = []

        for token in doc:
            if token.pos_ == "VERB" and token.lemma_ in self.malicious_verbs:
                for child in token.children:
                    if child.dep_ in ["dobj", "nsubjpass"]:
                        # Lấy toàn bộ cụm danh từ (ví dụ: "the heap address")
                        noun_phrase = "".join([t.text_with_ws for t in child.subtree]).strip().lower()
                        
                        # LỚP 2: Lọc rác và kiểm tra tính kỹ thuật
                        clean_phrase = self.clean_phrase(noun_phrase)
                        if clean_phrase and self.is_technical(clean_phrase):
                            critical_vars.append(clean_phrase)
        
        return list(set(critical_vars))

    def clean_phrase(self, text):
        stop_words = {"the", "a", "an", "some", "any", "this", "that", "stuff", "we", "will", "need", "to", "and"}
        words = text.split()
        # Chỉ giữ lại các từ không nằm trong stop_words
        important_words = [w for w in words if w not in stop_words]
        return " ".join(important_words)
    def normalize(self, var_list):
        normalized = set()
        for v in var_list:
            # Quy đổi các cụm từ phổ biến về chuẩn
            if "hook" in v:
                if "free" in v: normalized.add("free_hook")
                elif "malloc" in v: normalized.add("malloc_hook")
            elif "libc" in v:
                normalized.add("libc_base")
            elif "heap" in v:
                normalized.add("heap_base")
            elif "system" in v:
                normalized.add("system")
            # Nếu là các biến quan trọng khác thì giữ nguyên
            elif len(v.split()) == 1: 
                normalized.add(v)
        return list(normalized)

def run_scan(target_file, engine):
    # Đọc và xử lý một file cụ thể
    if not os.path.exists(target_file):
        print(f"[!] Không tìm thấy file '{target_file}'")
        return []
    
    with open(target_file, 'r', encoding='utf-8') as f:
        content = f.read()
        return engine.extract_from_text(content)

def main():
    engine = NLPEngine()
    writeup_dir = "../data/writeups"
    output_file = "../module3/critical_vars.txt"
    final_vars = []
    
    # Chế độ 1: Scan 1 file chỉ định (Ví dụ: python3 extract_vars.py writeup.txt)
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
        target_file = os.path.join(writeup_dir, target_file)
        print(f"[*] Đang quét file: {target_file}")
        final_vars = run_scan(target_file, engine)
        print(f"[+] Biến quan trọng tìm thấy: {final_vars}")

    # Chế độ 2: Full scan (Ví dụ: python3 extract_vars.py)
    else:
        print(f"[*] Đang quét toàn bộ thư mục: {writeup_dir}")
        all_vars = set()
        
        if not os.path.exists(writeup_dir):
            print(f"[!] Thư mục {writeup_dir} không tồn tại.")
            return

        for filename in os.listdir(writeup_dir):
            if filename.endswith(".txt"):
                file_path = os.path.join(writeup_dir, filename)
                print(f"  > Đang xử lý: {filename}")
                vars_in_file = run_scan(file_path, engine)
                all_vars.update(vars_in_file)
                print(f"\n[OK] Kết quả Full scan của {file_path} là: {list(all_vars)}")
        final_vars = list(all_vars)
        print(f"\n[100%] Full scan: {list(final_vars)}")
    # TRÍCH XUẤT RA FILE ../module3/critical_vars.txt
    if final_vars:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(str(final_vars))
        print(f"[OK] Đã trích xuất dữ liệu ra file '{output_file}' thành công!")
    else:
        print("[!] Tập hợp biến nguy hiểm bị rỗng.")

if __name__ == "__main__":
    main()