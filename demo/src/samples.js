export const DEFAULT_SAMPLE = {
  label: "Leak + UAF",
  code: `#include <stdlib.h>

void update_buffer(int flag) {
    char *buf = malloc(64);
    if (!buf) {
        return;
    }

    if (flag) {
        free(buf);
    }

    buf[0] = 'A';
}`,
};

export const SAMPLES = [
  DEFAULT_SAMPLE,
  {
    label: "Double free",
    code: `#include <stdlib.h>

void release_twice(void) {
    int *p = malloc(sizeof(int));
    free(p);
    free(p);
}`,
  },
  {
    label: "Unsafe API",
    code: `#include <stdio.h>

void read_name(void) {
    char name[32];
    gets(name);
}`,
  },
  {
    label: "Null check",
    code: `#include <stdlib.h>

void use_pointer(void) {
    int *value = malloc(sizeof(int));
    *value = 42;
    free(value);
}`,
  },
];