#ifndef READ_CONFIG_H
#define READ_CONFIG_H

int   init_augeas(void);
char *get_augeas(const char *key);
void  close_augeas(void);

#endif
