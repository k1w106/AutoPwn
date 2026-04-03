#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
// gcc -shared -fPIC ./hook.c -o ./hook.so -ldl
// Usage: LD_PRELOAD=./hook.so ./<binary_file>
//        LD_PRELOAD=./hook.so ./test 2> ../analyzer/trace.log

// Định nghĩa các con trỏ hàm để lưu giữ hàm trong libc
static void* (*real_malloc)(size_t) = NULL;
static void (*real_free)(void*) = NULL;

// Hàm khởi tạo sẽ chạy ngay khi thư viện được nạp
// RTLD_NEXT là chỉ thị để tìm hàm trong thư viện tiếp theo (libc.so) chứ không phải thư viện hiện tại là hook.so
void __attribute__((constructor)) init() {
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_free = dlsym(RTLD_NEXT, "free");
}
// Ghi đè malloc
void* malloc(size_t size) {
    if (!real_malloc){
        real_malloc = dlsym(RTLD_NEXT, "malloc");
    }
    void* ptr = real_malloc(size);
    
    // Ghi log ra stderr để không làm nhiễu stdout của chương trình
    // Định dạng: [AUTO_PWN] OP | SIZE | ADDR
    unsigned int offset_heap_base_239 = 0x290;
    fprintf(stderr, "[AUTO_PWN] Alloc | size = %zu bytes | address = %p\n", size, ptr);
    return ptr;
}
// Ghi đè free
void free(void* ptr) {
    if (!real_free) real_free = dlsym(RTLD_NEXT, "free");
    
    if (ptr) {
        fprintf(stderr, "[AUTO_PWN] Free  |                  | address = %p\n", ptr);
    }
    real_free(ptr);
}