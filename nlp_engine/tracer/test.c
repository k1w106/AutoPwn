#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
// gcc test.c -o test
// Đây là file dùng để test hook.c
void init(){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}
int main() {
    init();
    char greeting[] = "Hello world\n";
    write(1, greeting, 12);
    unsigned long *ptr = (unsigned long *)malloc(0x100); 
    memcpy(ptr, greeting, 12);
    free(ptr);
    return 0;
}