#include <pthread.h>
#include <stdio.h>
static void *dummy_thread_func(void *arg) { return NULL; }
int main() {
    pthread_t dummy_thread;
    pthread_create(&dummy_thread, NULL, dummy_thread_func, NULL);
    pthread_join(dummy_thread, NULL);
    printf("Dummy thread done.\n");
    return 0;
}
