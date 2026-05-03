#ifndef READ_CONFIG_H
#define READ_CONFIG_H

int   init_augeas(void);
char *get_augeas(const char *key);
void  close_augeas(void);

/* Read [global] <key> from /etc/postWolf/config, strip any http(s)://
 * prefix, and log the source to stderr.  Returns malloc'd host[:port]
 * (caller frees) or NULL if the key is missing. */
char *read_config_url(const char *key);

/* Read [global] <key> from /etc/postWolf/config and parse as a
 * positive integer.  Returns the value, or default_val if the key is
 * absent or unparseable.  Logs the source to stderr. */
long read_config_long(const char *key, long default_val);

/* Read [global] <key> from /etc/postWolf/config as a string.  Returns
 * a malloc'd copy of the value (caller frees), or a malloc'd copy of
 * default_val if the key is absent.  Logs the source to stderr. */
char *read_config_str(const char *key, const char *default_val);

/* Pure parse helper (exposed for unit testing).  Parses raw as a
 * positive integer.  Returns 0 and writes *out on success; returns -1
 * (out untouched) on invalid input (non-numeric, leading/trailing
 * garbage, zero, or negative). */
int parse_long_strict(const char *raw, long *out);

#endif
