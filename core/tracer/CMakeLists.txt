cmake_minimum_required(VERSION 3.10)
project(heap_tracer)

# ── Find DynamoRIO ───────────────────────────────────────────────────────
# Pass -DDynamoRIO_DIR=$DYNAMORIO_HOME/cmake when running cmake
find_package(DynamoRIO REQUIRED)

# ── Client target ────────────────────────────────────────────────────────
add_library(heap_tracer SHARED heap_tracer.c)

# Configure as a DynamoRIO client (sets correct flags, includes, etc.)
configure_DynamoRIO_client(heap_tracer)

# ── Extension: drmgr (module load events) ───────────────────────────────
use_DynamoRIO_extension(heap_tracer drmgr)

# ── Extension: drwrap (function wrapping) ────────────────────────────────
use_DynamoRIO_extension(heap_tracer drwrap)

# ── Extension: drsyms (symbol lookup, optional) ─────────────────────────
use_DynamoRIO_extension(heap_tracer drsyms)
