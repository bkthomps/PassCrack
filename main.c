#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>

#define LOWER_CASE "abcdefghijklmnopqrstuvwxyz"
#define UPPER_CASE "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define NUMBERS "0123456789"
#define COMMON_SPECIAL_CHARACTERS "~!@#$%^&*()"
#define UNCOMMON_SPECIAL_CHARACTERS " `-_+=[]{}:;'\",.<>/?\\|"

struct thread_payload {
    unsigned int thread_id;
    unsigned int thread_count;
    const char *user_password;
    char *printable_charset;
    size_t printable_length;
};

static inline bool hash_equal(const char *const user_password,
                              const char *const brute_password)
{
    // This could compare two hashes instead of two plain text passwords
    return strcmp(user_password, brute_password) == 0;
}

static inline bool continue_brute_force(const char *const user_password,
                                        const unsigned int length,
                                        const char preset,
                                        const char *const printable_charset,
                                        const int printable_length)
{
    const char printable_start = printable_charset[0];
    int brute_index[length - 1];
    memset(brute_index, 0, sizeof(int) * (length - 1));
    brute_index[0]--;
    char brute_password[length + 1];
    brute_password[length] = '\0';
    brute_password[length - 1] = preset;
    memset(brute_password, printable_start, length - 1);
    while (true) {
        int index = 0;
        while (brute_index[index] == printable_length - 1) {
            brute_index[index] = 0;
            brute_password[index] = printable_start;
            index++;
            if (index == length - 1) {
                return true;
            }
        }
        brute_index[index]++;
        brute_password[index] = printable_charset[brute_index[index]];
        if (hash_equal(user_password, brute_password)) {
            printf("The password is: %s\n", brute_password);
            return false;
        }
    }
}

static inline bool one_character(const char *const user_password,
                                 const char min, const char max,
                                 const char *const printable_charset)
{
    char single_character[] = {'\0', '\0'};
    for (int i = min; i <= max; i++) {
        single_character[0] = printable_charset[i];
        if (hash_equal(user_password, single_character)) {
            printf("The password is: %s\n", single_character);
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
    const size_t printable_length = payload->printable_length;
    char printable_charset[printable_length + 1];
    memcpy(printable_charset, payload->printable_charset, printable_length + 1);
    free(payload->printable_charset);
    free(payload);
    const double diff = ((double) printable_length / thread_count);
    const char min = (char) (diff * thread_id);
    const char max = (char) (diff * (thread_id + 1) - 1);
    if (one_character(user_password, min, max, printable_charset)) {
        exit(0);
    }
    unsigned int length = 2;
    while (true) {
        for (int i = min; i <= max; i++) {
            if (!continue_brute_force(user_password, length,
                                      printable_charset[i], printable_charset,
                                      printable_length)) {
                exit(0);
            }
        }
        length++;
    }
}

static inline void start_threads(const unsigned int thread_count,
                                 const char *const user_password,
                                 char *const printable_charset,
                                 const size_t printable_length)
{
    pthread_t threads[thread_count];
    for (int i = 0; i < thread_count; i++) {
        struct thread_payload *const payload = malloc(sizeof(*payload));
        payload->thread_id = i;
        payload->thread_count = thread_count;
        payload->user_password = user_password;
        payload->printable_charset = malloc(printable_length + 1);
        memcpy(payload->printable_charset, printable_charset,
               printable_length + 1);
        payload->printable_length = printable_length;
        pthread_create(&threads[i], NULL, thread, payload);
    }
    free(printable_charset);
    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
}

static inline unsigned int get_system_thread_count()
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

static inline int get_thread_count(long thread_count_arg,
                                   const size_t printable_length)
{
    if (thread_count_arg > 0) {
        if (thread_count_arg > printable_length) {
            printf("Error: cannot use %ld threads since the thread count must "
                   "be a positive integer which is less than or equal to %zu\n",
                   thread_count_arg, printable_length);
            return -1;
        }
        return (int) thread_count_arg;
    }
    long thread_count = get_system_thread_count();
    if (thread_count > printable_length) {
        thread_count = printable_length;
    }
    if (thread_count <= 0) {
        printf("Error: could not retrieve thread count\n");
        return -2;
    }
    return (int) thread_count;
}

static inline char *get_charset(const int argc, char *const *const argv,
                                long *thread_count_arg)
{
    bool include_lower_case = true;
    bool include_upper_case = true;
    bool include_numeric = true;
    long special_level = 0;
    char *extra = NULL;
    for (int i = 2; i < argc; i++) {
        char *const argument = argv[i];
        const char copy[strlen(argument) + 1];
        memcpy((void *) copy, argument, strlen(argument) + 1);
        char *token = strtok(argument, "=");
        if (!token) {
            goto error;
        }
        const char *const type = token;
        token = strtok(NULL, "=");
        if (!token) {
            goto error;
        }
        char *const value = token;
        token = strtok(NULL, "=");
        if (token) {
            goto error;
        }
        if (strcmp(type, "extra") == 0) {
            extra = value;
            continue;
        }
        char *end;
        const long numeric = strtol(value, &end, 10);
        if (*end || numeric < 0) {
            // Only need these checks, since an argument will not be empty
            goto error;
        }
        if (numeric != 0 && strcmp(type, "thread") == 0) {
            *thread_count_arg = numeric;
            continue;
        }
        if (numeric > 2) {
            goto error;
        }
        if (strcmp(type, "special") == 0) {
            special_level = numeric;
            continue;
        }
        if (numeric > 1) {
            goto error;
        }
        if (strcmp(type, "lower") == 0) {
            include_lower_case = numeric;
            continue;
        }
        if (strcmp(type, "upper") == 0) {
            include_upper_case = numeric;
            continue;
        }
        if (strcmp(type, "numeric") == 0) {
            include_numeric = numeric;
            continue;
        }
        error:
        printf("Error: invalid argument '%s'\n", copy);
        return NULL;
    }
    size_t length = 0;
    if (include_lower_case) {
        length += strlen(LOWER_CASE);
    }
    if (include_upper_case) {
        length += strlen(UPPER_CASE);
    }
    if (include_numeric) {
        length += strlen(NUMBERS);
    }
    if (special_level >= 1) {
        length += strlen(COMMON_SPECIAL_CHARACTERS);
    }
    if (special_level >= 2) {
        length += strlen(UNCOMMON_SPECIAL_CHARACTERS);
    }
    if (extra) {
        length += strlen(extra);
    }
    char *const charset = malloc(length + 1);
    charset[length] = '\0';
    int index = 0;
    if (include_lower_case) {
        const int size = strlen(LOWER_CASE);
        memcpy(charset + index, LOWER_CASE, size);
        index += size;
    }
    if (include_upper_case) {
        const int size = strlen(UPPER_CASE);
        memcpy(charset + index, UPPER_CASE, size);
        index += size;
    }
    if (include_numeric) {
        const int size = strlen(NUMBERS);
        memcpy(charset + index, NUMBERS, size);
        index += size;
    }
    if (special_level >= 1) {
        const int size = strlen(COMMON_SPECIAL_CHARACTERS);
        memcpy(charset + index, COMMON_SPECIAL_CHARACTERS, size);
        index += size;
    }
    if (special_level >= 2) {
        const int size = strlen(UNCOMMON_SPECIAL_CHARACTERS);
        memcpy(charset + index, UNCOMMON_SPECIAL_CHARACTERS, size);
        index += size;
    }
    if (extra) {
        memcpy(charset + index, extra, strlen(extra));
    }
    return charset;
}

int main(const int argc, char *const *const argv)
{
    if (argc < 2) {
        printf("Error: specify a password to crack\n");
        return -1;
    }
    long thread_count_arg = -1;
    char *const printable_charset = get_charset(argc, argv, &thread_count_arg);
    if (!printable_charset) {
        return -2;
    }
    const size_t printable_length = strlen(printable_charset);
    if (printable_length == 0) {
        printf("Error: a character set of size 0 was specified\n");
        return -3;
    }
    const int thread_count =
            get_thread_count(thread_count_arg, printable_length);
    if (thread_count <= 0) {
        return -4;
    }
    printf("Using %zu long character set: %s\n", printable_length,
           printable_charset);
    printf("Brute forcing with %d threads\n", thread_count);
    start_threads(thread_count, argv[1], printable_charset, printable_length);
    return 0;
}
