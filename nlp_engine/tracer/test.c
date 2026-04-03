#include <stdio.h>
#include <stdlib.h>
// gcc test.c -o test
// Đây là file dùng để test hook.c
void init(){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}
int main() {
    init();
    puts("Hello world");
    unsigned long *ptr = (unsigned long *)malloc(0x100); 
    free(ptr);
    return 0;
}