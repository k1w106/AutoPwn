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
            # python3 -m spacy download en_core_web_sm
            sys.exit(1)
        
        # Danh sách các động từ độc hại ban đầu (trích từ paper)
        self.malicious_verbs = {"overwrite", "corrupt", "modify", 
                                "hijack", "leak", "control"
                                }

    def extract_from_text(self, text):
        # Phân tích cú pháp để tìm cụm Verb-Object
        doc = self.nlp(text)
        critical_vars = []

        for token in doc:
            # Kiểm tra nếu từ là Động từ và nằm trong danh sách độc hại
            if token.pos_ == "VERB" and token.lemma_ in self.malicious_verbs:
                # Tìm Tân ngữ trực tiếp (dobj) của động từ đó 
                for child in token.children:
                    if child.dep_ == "dobj":
                        critical_vars.append(child.text)
        
        return list(set(critical_vars))

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
    writeup_dir = "./data/writeups"
    output_file = "./analyzer/critical_vars.txt"
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
    # TRÍCH XUẤT RA FILE ./analyzer/critical_vars.txt
    if final_vars:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(str(final_vars))
        print(f"[OK] Đã trích xuất dữ liệu ra file '{output_file}' thành công!")
    else:
        print("[!] Tập hợp biến nguy hiểm bị rỗng.")

if __name__ == "__main__":
    main()