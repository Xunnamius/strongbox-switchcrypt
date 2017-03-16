#ifndef BLFS_BUSELFS_H_
#define BLFS_BUSELFS_H_

#include "constants.h"

int buse_read(void * buffer, uint32_t len, uint64_t offset, void * userdata);
int buse_write(const void * buffer, uint32_t len, uint64_t offset, void * userdata);
void buse_disc(void * userdata);
int buse_flush(void * userdata);
int buse_trim(uint64_t from, uint32_t len, void * userdata);
void rekey_nugget_journaled();
void password_verify();

int buselfs_main(int argc, char * argv[]);

#endif /* BLFS_BUSELFS_H_ */
