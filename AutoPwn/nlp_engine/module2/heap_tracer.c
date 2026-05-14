/*
 * AutoPwn – Module 2: DynamoRIO Heap Tracer
 * ==========================================
 * Traces malloc, free, calloc, realloc, read, write, memcpy
 * for any binary regardless of libc namespace.
 *
 * Build:
 *   mkdir build && cd build
 *   cmake .. -DDynamoRIO_DIR=$DYNAMORIO_HOME/cmake
 *   make
 *
 * Run:
 *   $DYNAMORIO_HOME/bin64/drrun -c ./libheap_tracer.so -- ./chall_patched
 *
 * Output: /tmp/autopwn_trace.log (or $AUTOPWN_LOG)
 */

#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#include "drsyms.h"

#include <string.h>
#include <stdint.h>
#include <stdarg.h>

#ifndef OUT
#define OUT
#endif

/* ── State ──────────────────────────────────────────────────────────── */
static file_t    log_fd   = INVALID_FILE;
static uint64    seq      = 0;
static void     *seq_lock = NULL;

/* ── Per-call scratch (stored in wrap user_data) ─────────────────────── */
typedef struct { size_t arg0; size_t arg1; } call_args_t;

/* ═══════════════════════════════════════════════════════════════════════
 * Tiny formatters (no libc printf — keeps us re-entrancy-safe)
 * ═══════════════════════════════════════════════════════════════════════ */

static int mini_snprintf(char *buf, size_t max, const char *fmt, ...) {
    /* Extremely basic snprintf for our needs: %s, %u (64), %x (hex64), %d */
    va_list ap;
    va_start(ap, fmt);
    size_t i = 0;
    while (*fmt && i < max - 1) {
        if (*fmt == '%') {
            fmt++;
            if (*fmt == 's') {
                const char *s = va_arg(ap, const char *);
                while (s && *s && i < max - 1) buf[i++] = *s++;
            } else if (*fmt == 'u') {
                uint64 v = va_arg(ap, uint64);
                if (v == 0) buf[i++] = '0';
                else {
                    char tmp[24]; int ti=0;
                    while(v){ tmp[ti++]=(char)('0'+(v%10)); v/=10; }
                    while(ti>0 && i < max - 1) buf[i++]=tmp[--ti];
                }
            } else if (*fmt == 'x') {
                uint64 v = va_arg(ap, uint64);
                buf[i++] = '0'; if (i < max - 1) buf[i++] = 'x';
                const char *h = "0123456789abcdef";
                for (int s=60; s>=0; s-=4) {
                    if (i < max - 1) buf[i++] = h[(v >> s) & 0xf];
                }
            } else if (*fmt == 'd') {
                int v = va_arg(ap, int);
                if (v < 0) { buf[i++] = '-'; v = -v; }
                if (v == 0) buf[i++] = '0';
                else {
                    char tmp[12]; int ti=0;
                    while(v){ tmp[ti++]=(char)('0'+(v%10)); v/=10; }
                    while(ti>0 && i < max - 1) buf[i++]=tmp[--ti];
                }
            }
        } else {
            buf[i++] = *fmt;
        }
        fmt++;
    }
    buf[i] = '\0';
    va_end(ap);
    return (int)i;
}

static void bytes_to_hex(const void *buf, size_t n, char *out) {
    if (!buf || n == 0) { out[0] = '-'; out[1] = '\0'; return; }
    const unsigned char *p = (const unsigned char*)buf;
    size_t take = n < 8 ? n : 8;
    out[0] = '0'; out[1] = 'x';
    const char *h = "0123456789abcdef";
    for (size_t i = 0; i < take; i++) {
        out[2 + i * 2]     = h[p[i] >> 4];
        out[2 + i * 2 + 1] = h[p[i] & 0xf];
    }
    out[2 + take * 2] = '\0';
}

/* ═══════════════════════════════════════════════════════════════════════
 * Logging
 * ═══════════════════════════════════════════════════════════════════════ */

static void log_event(const char *type, size_t size,
                      uint64 addr, const void *content_buf) {
    char line[1024];
    char s_content[32];
    const char *comm = dr_get_application_name();

    dr_mutex_lock(seq_lock);
    uint64 cur = seq++;
    dr_mutex_unlock(seq_lock);

    if (content_buf) {
        bytes_to_hex(content_buf, size < 8 ? size : 8, s_content);
    } else {
        s_content[0] = '\0';
    }

    /* Format: SEQ | PID | COMM | TYPE | size=N | addr=0x... [| content=0x...] */
    int len = mini_snprintf(line, sizeof(line),
        "%u | %u | %s | %s | size=%u | addr=%x",
        cur, (uint64)dr_get_process_id(), comm, type, (uint64)size, addr);

    if (s_content[0]) {
        int clen = mini_snprintf(line + len, sizeof(line) - len, " | content=%s", s_content);
        len += clen;
    }
    
    if (len < (int)sizeof(line) - 1) {
        line[len++] = '\n';
        line[len] = '\0';
    }

    /* Single write is more atomic across processes */
    dr_write_file(log_fd, line, len);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Hooks
 * ═══════════════════════════════════════════════════════════════════════ */

static void malloc_pre(void *wrapctx, OUT void **user_data) {
    call_args_t *a = dr_global_alloc(sizeof(call_args_t));
    a->arg0 = (size_t)drwrap_get_arg(wrapctx, 0);
    *user_data = a;
}
static void malloc_post(void *wrapctx, void *user_data) {
    call_args_t *a = (call_args_t *)user_data;
    uint64 ptr = (uint64)(uintptr_t)drwrap_get_retval(wrapctx);
    log_event("Alloc", a->arg0, ptr, NULL);
    dr_global_free(a, sizeof(call_args_t));
}

static void calloc_pre(void *wrapctx, OUT void **user_data) {
    call_args_t *a = dr_global_alloc(sizeof(call_args_t));
    a->arg0 = (size_t)drwrap_get_arg(wrapctx, 0);
    a->arg1 = (size_t)drwrap_get_arg(wrapctx, 1);
    *user_data = a;
}
static void calloc_post(void *wrapctx, void *user_data) {
    call_args_t *a = (call_args_t *)user_data;
    uint64 ptr = (uint64)(uintptr_t)drwrap_get_retval(wrapctx);
    log_event("Calloc", a->arg0 * a->arg1, ptr, NULL);
    dr_global_free(a, sizeof(call_args_t));
}

static void realloc_pre(void *wrapctx, OUT void **user_data) {
    call_args_t *a = dr_global_alloc(sizeof(call_args_t));
    a->arg0 = (size_t)drwrap_get_arg(wrapctx, 1);
    *user_data = a;
}
static void realloc_post(void *wrapctx, void *user_data) {
    call_args_t *a = (call_args_t *)user_data;
    uint64 ptr = (uint64)(uintptr_t)drwrap_get_retval(wrapctx);
    log_event("Realloc", a->arg0, ptr, NULL);
    dr_global_free(a, sizeof(call_args_t));
}

static void free_pre(void *wrapctx, OUT void **user_data) {
    uint64 ptr = (uint64)(uintptr_t)drwrap_get_arg(wrapctx, 0);
    if (ptr) {
        /* In many cases, peek first 8 bytes (Safe Linking FD etc) */
        log_event("Free", 0, ptr, (void *)(uintptr_t)ptr);
    }
    *user_data = NULL;
}

static void read_pre(void *wrapctx, OUT void **user_data) {
    call_args_t *a = dr_global_alloc(sizeof(call_args_t));
    a->arg0 = (size_t)drwrap_get_arg(wrapctx, 0);               /* fd  */
    a->arg1 = (size_t)(uintptr_t)drwrap_get_arg(wrapctx, 1);    /* buf */
    *user_data = a;
}
static void read_post(void *wrapctx, void *user_data) {
    call_args_t *a = (call_args_t *)user_data;
    ssize_t ret = (ssize_t)(uintptr_t)drwrap_get_retval(wrapctx);
    if (ret > 0 && (a->arg0 == 0 || a->arg0 > 2)) {
        log_event("Read", (size_t)ret, (uint64)a->arg1, (void *)(uintptr_t)a->arg1);
    }
    dr_global_free(a, sizeof(call_args_t));
}

static void write_pre(void *wrapctx, OUT void **user_data) {
    call_args_t *a = dr_global_alloc(sizeof(call_args_t));
    a->arg0 = (size_t)drwrap_get_arg(wrapctx, 0);               /* fd  */
    a->arg1 = (size_t)(uintptr_t)drwrap_get_arg(wrapctx, 1);    /* buf */
    *user_data = a;
}
static void write_post(void *wrapctx, void *user_data) {
    call_args_t *a = (call_args_t *)user_data;
    ssize_t ret = (ssize_t)(uintptr_t)drwrap_get_retval(wrapctx);
    if (ret > 0 && (a->arg0 == 1 || a->arg0 == 2)) {
        log_event("Leak", (size_t)ret, (uint64)a->arg1, (void *)(uintptr_t)a->arg1);
    }
    dr_global_free(a, sizeof(call_args_t));
}

static void memcpy_pre(void *wrapctx, OUT void **user_data) {
    call_args_t *a = dr_global_alloc(sizeof(call_args_t));
    a->arg0 = (size_t)(uintptr_t)drwrap_get_arg(wrapctx, 0);   /* dest */
    a->arg1 = (size_t)drwrap_get_arg(wrapctx, 2);               /* n    */
    *user_data = a;
}
static void memcpy_post(void *wrapctx, void *user_data) {
    call_args_t *a = (call_args_t *)user_data;
    void *src = drwrap_get_arg(wrapctx, 1);
    log_event("Copy", a->arg1, (uint64)a->arg0, src);
    dr_global_free(a, sizeof(call_args_t));
}

/* ═══════════════════════════════════════════════════════════════════════
 * Module-load & Memory Mapping
 * ═══════════════════════════════════════════════════════════════════════ */

static void log_map(const char *name, uint64 start, uint64 end) {
    char line[1024];
    int len = mini_snprintf(line, sizeof(line),
        "MAP | %s | %x | %x\n", name, start, end);
    dr_write_file(log_fd, line, len);
}

static void log_current_modules() {
    dr_module_iterator_t *mi = dr_module_iterator_start();
    while (dr_module_iterator_hasnext(mi)) {
        module_data_t *mod = dr_module_iterator_next(mi);
        if (mod) {
            const char *name = dr_module_preferred_name(mod);
            log_map(name, (uint64)mod->start, (uint64)mod->end);
            dr_free_module_data(mod);
        }
    }
    dr_module_iterator_stop(mi);
}

static void wrap_if_found(const module_data_t *mod, const char *name,
                          void (*pre)(void*, void**), void (*post)(void*, void*)) {
    app_pc addr = (app_pc)dr_get_proc_address(mod->handle, name);
    if (addr) drwrap_wrap(addr, pre, post);
}

static void on_module_load(void *drcontext, const module_data_t *mod, bool loaded) {
    const char *name = dr_module_preferred_name(mod);
    log_map(name, (uint64)mod->start, (uint64)mod->end);

    wrap_if_found(mod, "malloc",   malloc_pre,  malloc_post);
    wrap_if_found(mod, "calloc",   calloc_pre,  calloc_post);
    wrap_if_found(mod, "realloc",  realloc_pre, realloc_post);
    wrap_if_found(mod, "free",     free_pre,    NULL);
    wrap_if_found(mod, "read",     read_pre,    read_post);
    wrap_if_found(mod, "write",    write_pre,   write_post);
    wrap_if_found(mod, "memcpy",   memcpy_pre,  memcpy_post);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Entry / Exit
 * ═══════════════════════════════════════════════════════════════════════ */

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_set_client_name("AutoPwn Heap Tracer", "");
    drmgr_init();
    drwrap_init();
    seq_lock = dr_mutex_create();

    const char *log_path = getenv("AUTOPWN_LOG");
    if (!log_path || !log_path[0]) log_path = "/tmp/autopwn_trace.log";
    
    /* Use APPEND so shell/children don't overwrite target log */
    log_fd = dr_open_file(log_path, DR_FILE_WRITE_APPEND | DR_FILE_ALLOW_LARGE);
    
    if (log_fd != INVALID_FILE) {
        dr_fprintf(STDERR, "[AutoPwn] Logging to: %s\n", log_path);
        
        /* Log initial memory map */
        log_current_modules();
    }
    drmgr_register_module_load_event(on_module_load);
}

DR_EXPORT void dr_client_exit(void) {
    dr_close_file(log_fd);
    dr_mutex_destroy(seq_lock);
    drwrap_exit();
    drmgr_exit();
}
