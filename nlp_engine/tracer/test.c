#include <stdio.h>
#include <stdlib.h>
// gcc test.c -o test
int main() {
    printf(" [*] Malloc(0x100) from test file\n");
    unsigned long *ptr = (unsigned long *)malloc(0x100); 
    printf("[TEST_FILE] Malloc first chunk is %p\n", (void *)ptr);
    printf("[TEST_FILE] Free from test file\n");
    free(ptr);
    return 0;
}