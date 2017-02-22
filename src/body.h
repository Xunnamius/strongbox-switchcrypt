#ifndef BODY_H
#define BODY_H

#include <stdint.h>
#include "io.h"

/**
 * struct buselfs_nugget
 *
 * @global_id       the global ID that ties keystore, journal, and nugget
 * @data_offset     data offset in the backstore
 * @data_length     total length of the nugget in the backstore
 * @backstore       the backstore itself
 * @is_open         if this struct has had its members free()'d (0 = yes)
 */
typedef struct buselfs_nugget
{
    uint64_t global_id;
    uint64_t data_offset;
    uint64_t data_length;

    buselfs_backstore * backstore;

    char is_open;
} buselfs_nugget;

int buselfs_open_nugget(buselfs_backstore * backstore, int global_id, buselfs_nugget * nugget);
int buselfs_commit_nugget(buselfs_nugget * nugget);
int buselfs_close_nugget(buselfs_nugget * nugget);
int buselfs_read_from_reserved_nugget_space(buselfs_backstore * backstore, buselfs_nugget * nugget);
int buselfs_write_to_reserved_nugget_space(buselfs_nugget * nugget);
int buselfs_read_nugget_data(buselfs_nugget * nugget, char * data);
int buselfs_write_nugget_data(buselfs_nugget * nugget, const char * data);

#endif /* BODY_H */
