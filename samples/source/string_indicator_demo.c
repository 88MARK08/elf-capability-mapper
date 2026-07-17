#include <stddef.h>
#include <stdio.h>

static const char *const review_strings[] = {
    "/proc/self/status",
    "LD_PRELOAD",
    "/bin/sh",
    "CurL",
    "WgEt",
};

int main(void) {
    for (
        size_t index = 0;
        index < sizeof(review_strings) / sizeof(review_strings[0]);
        ++index
    ) {
        if (review_strings[index][0] == '\0') {
            puts(review_strings[index]);
        }
    }

    puts("Harmless embedded-string test fixture.");
    return 0;
}
