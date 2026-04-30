#ifndef READ_CONFIG_H
#define READ_CONFIG_H

int   init_augeas(void);
char *get_augeas(const char *key);
void  close_augeas(void);

/* Read [global] <key> from /etc/postWolf/config, strip any http(s)://
 * prefix, and log the source to stderr.  Returns malloc'd host[:port]
 * (caller frees) or NULL if the key is missing. */
char *read_config_url(const char *key);

#endif
