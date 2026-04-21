#include <stdio.h>
extern unsigned long getauxval(unsigned long type);
int main() {
    printf("%p\n", getauxval);
    return 0;
}
