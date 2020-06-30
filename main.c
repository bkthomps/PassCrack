#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>

#define PRINTABLE_MIN 32
#define PRINTABLE_MAX 126
#define PRINTABLE_RANGE (PRINTABLE_MAX - PRINTABLE_MIN + 1)

struct thread_payload {
    unsigned int thread_id;
    unsigned int thread_count;
    const char *user_password;
};

static inline bool hash_equal(const char *const user_password,
                              const char *const brute_password)
{
    // This could compare two hashes instead of two plain text passwords
    return strcmp(user_password, brute_password) == 0;
}

static inline bool continue_brute_force(const char *const user_password,
                                        const unsigned int length,
                                        const char preset)
{
    char brute_password[length + 1];
    brute_password[length] = '\0';
    brute_password[length - 1] = preset;
    memset(brute_password, PRINTABLE_MIN, length - 1);
    brute_password[0]--;
    while (true) {
        int index = 0;
        while (brute_password[index] == PRINTABLE_MAX) {
            brute_password[index] = PRINTABLE_MIN;
            index++;
            if (index == length - 1) {
                return true;
            }
        }
        brute_password[index]++;
        if (hash_equal(user_password, brute_password)) {
            printf("The password is: %s\n", brute_password);
            return false;
        }
    }
}

static inline bool one_character(const char *const user_password,
                                 const char min, const char max)
{
    char one_letter[] = {'\0', '\0'};
    for (char c = min; c <= max; c++) {
        one_letter[0] = c;
        if (hash_equal(user_password, one_letter)) {
            printf("The password is: %s\n", one_letter);
            return true;
        }
    }
    return false;
}

static void *thread(void *const ptr)
{
    struct thread_payload *const payload = ptr;
    const unsigned int thread_id = payload->thread_id;
    const unsigned int thread_count = payload->thread_count;
    const char *const user_password = payload->user_password;
    free(payload);
    const double diff = ((double) PRINTABLE_RANGE / thread_count);
    const char min = PRINTABLE_MIN + diff * thread_id;
    const char max = PRINTABLE_MIN + diff * (thread_id + 1) - 1;
    if (one_character(user_password, min, max)) {
        exit(0);
    }
    unsigned int length = 2;
    while (true) {
        for (char c = min; c <= max; c++) {
            if (!continue_brute_force(user_password, length, c)) {
                exit(0);
            }
        }
        length++;
    }
}

static inline void start_threads(const unsigned int thread_count,
                                 const char *const user_password)
{
    pthread_t threads[thread_count];
    for (int i = 0; i < thread_count; i++) {
        struct thread_payload *const payload = malloc(sizeof(*payload));
        payload->thread_id = i;
        payload->thread_count = thread_count;
        payload->user_password = user_password;
        pthread_create(&threads[i], NULL, thread, payload);
    }
    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
}

static inline unsigned int get_thread_count()
{
    unsigned int eax = 11;
    unsigned int ebx = 0;
    unsigned int ecx = 1;
    unsigned int edx = 0;
    asm volatile("cpuid"
    : "=a" (eax),
    "=b" (ebx),
    "=c" (ecx),
    "=d" (edx)
    : "0" (eax), "2" (ecx));
    return ebx;
}

int main(const int argc, const char *const *const argv)
{
    if (argc != 2 && argc != 3) {
        printf("Error: specify a password to crack\n");
        return -1;
    }
    unsigned int thread_count;
    if (argc == 3) {
        thread_count = strtol(argv[2], NULL, 10);
        if (thread_count == 0) {
            printf("Error: thread count must be a positive integer which is "
                   "less or equal to %d\n", PRINTABLE_RANGE);
            return -2;
        }
        if (thread_count > PRINTABLE_RANGE) {
            printf("Error: cannot use %d threads since the thread count must "
                   "be a positive integer which is less than or equal to %d\n",
                   thread_count, PRINTABLE_RANGE);
            return -3;
        }
    } else {
        thread_count = get_thread_count();
        if (thread_count > PRINTABLE_RANGE) {
            thread_count = PRINTABLE_RANGE;
        }
        if (thread_count == 0) {
            printf("Error: could not retrieve thread count\n");
            return -4;
        }
    }
    printf("Brute forcing with %d threads\n", thread_count);
    start_threads(thread_count, argv[1]);
    return 0;
}
