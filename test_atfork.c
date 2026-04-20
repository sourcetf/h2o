#include <pthread.h>
#include <stdio.h>
int main() {
    printf("%p\n", pthread_atfork);
    return 0;
}
