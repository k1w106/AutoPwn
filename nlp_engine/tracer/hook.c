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
static void (*real_read)(void*) = NULL;
static void (*real_memcpy)(void*) = NULL;
static void (*real_write)(void*) = NULL;

// Hàm khởi tạo sẽ chạy ngay khi thư viện được nạp
// RTLD_NEXT là chỉ thị để tìm hàm trong thư viện tiếp theo (libc.so) chứ không phải thư viện hiện tại là hook.so
void __attribute__((constructor)) init() {
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_free = dlsym(RTLD_NEXT, "free");
    real_read = dlsym(RTLD_NEXT, "read");
    real_memcpy = dlsym(RTLD_NEXT, "memcpy");
    real_write = dlsym(RTLD_NEXT, "write");
}
// Malloc
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
// Free
void free(void* ptr) {
    if (!real_free) real_free = dlsym(RTLD_NEXT, "free");
    
    if (ptr) {
        fprintf(stderr, "[AUTO_PWN] Free  |                 | address = %p\n", ptr);
    }
    real_free(ptr);
}
// --- Read data functions (Input/Write) ---
// From input user
// Read
ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real_read)(int, void *, size_t) = NULL;
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");

    ssize_t ret = real_read(fd, buf, count);

    if (ret > 0 && (fd == 0 || fd > 2)) { // Chỉ log stdin hoặc socket
        fprintf(stderr, "[AUTO_PWN] Write | size = %ld bytes | buffer = %p | type = read\n", 
                ret, buf);
    }
    return ret;
}
// From source -> dest
// Memcpy
void *memcpy(void *dest, const void *src, size_t n) {
    static void *(*real_memcpy)(void *, const void *, size_t) = NULL;
    if (!real_memcpy) real_memcpy = dlsym(RTLD_NEXT, "memcpy");

    void *ret = real_memcpy(dest, src, n);
    
    fprintf(stderr, "[AUTO_PWN] Copy  | size = %ld bytes | dest = %p | source = %p | type = memcpy \n", 
            n, dest, src);
    return ret;
}
// --- Print data functions (Output/Read) ---
// Write
ssize_t write(int fd, const void *buf, size_t count) {
    static ssize_t (*real_write)(int, const void *, size_t) = NULL;
    if (!real_write) real_write = dlsym(RTLD_NEXT, "write");
    // Log lại khi chương trình in dữ liệu ra (để tìm leak địa chỉ)
    if (fd == 1 || fd == 2) {
        fprintf(stderr, "[AUTO_PWN] Leak  | size = %ld bytes | address = %p | type = write\n", count, buf);
    }
    return real_write(fd, buf, count);
}
