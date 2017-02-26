#ifndef CRYPT_H
#define CRYPT_H

#include <stdint.h>
#include "cexception_configured.h"

void buselfs_passwd_to_secret(const char * passwd, char * secret);
void buselfs_generate_key_from_count(const char * secret, uint64_t count, const char * data);

#endif /* CRYPT_H */
