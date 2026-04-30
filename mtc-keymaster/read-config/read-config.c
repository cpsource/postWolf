#include "read-config.h"

#include <augeas.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_PREFIX "/files/etc/postWolf/config/"

static augeas *aug;

int init_augeas(void) {
    if (aug)
        return 0;
    aug = aug_init(NULL, NULL, AUG_NONE);
    if (!aug)
        return -1;
    return 0;
}

void close_augeas(void) {
    if (aug) {
        aug_close(aug);
        aug = NULL;
    }
}

char *get_augeas(const char *key) {
    if (!aug || !key)
        return NULL;

    char path[512];
    int n = snprintf(path, sizeof(path), "%s%s", CONFIG_PREFIX, key);
    if (n < 0 || (size_t)n >= sizeof(path))
        return NULL;

    const char *value = NULL;
    if (aug_get(aug, path, &value) != 1 || !value)
        return NULL;

    return strdup(value);
}

char *read_config_url(const char *key) {
    if (init_augeas() != 0)
        return NULL;
    char *raw = get_augeas(key);
    close_augeas();
    if (!raw)
        return NULL;

    fprintf(stderr, "Using %s from /etc/postWolf/config: %s\n", key, raw);

    const char *p = raw;
    if (strncmp(p, "https://", 8) == 0) p += 8;
    else if (strncmp(p, "http://",  7) == 0) p += 7;
    if (p != raw)
        memmove(raw, p, strlen(p) + 1);

    return raw;
}

#ifdef TEST_MAIN
int main(void) {
    if (init_augeas() != 0) {
        fprintf(stderr, "init_augeas failed\n");
        return 1;
    }

    const char *keys[] = { "global/url-bootstrap", "global/does-not-exist" };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        char *v = get_augeas(keys[i]);
        printf("%-25s = %s\n", keys[i], v ? v : "(not found)");
        free(v);
    }

    close_augeas();
    return 0;
}
#endif
