#include <stdio.h>
extern int __isthreaded;
int main() {
    printf("__isthreaded = %d\n", __isthreaded);
    return 0;
}
