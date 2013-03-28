#ifndef LINUX_BLOCKCONSOLE_H
#define LINUX_BLOCKCONSOLE_H

int bcon_magic_present(const void *data);
void bcon_add(const char *name);

#endif
