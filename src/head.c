/*
 * <description>
 *
 * @author Bernard Dickens
 */

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "head.h"
#include "bitmask.h"

// Static constant ordering
static const uint32_t header_types_ordered[BLFS_HEAD_NUM_HEADERS][2] = {
    { BLFS_HEAD_HEADER_TYPE_VERSION, BLFS_HEAD_HEADER_BYTES_VERSION },
    { BLFS_HEAD_HEADER_TYPE_SALT, BLFS_HEAD_HEADER_BYTES_SALT },
    { BLFS_HEAD_HEADER_TYPE_MTRH, BLFS_HEAD_HEADER_BYTES_MTRH },
    { BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER, BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER },
    { BLFS_HEAD_HEADER_TYPE_VERIFICATION, BLFS_HEAD_HEADER_BYTES_VERIFICATION },
    { BLFS_HEAD_HEADER_TYPE_NUMNUGGETS, BLFS_HEAD_HEADER_BYTES_NUMNUGGETS },
    { BLFS_HEAD_HEADER_TYPE_FLAKESPERNUGGET, BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET },
    { BLFS_HEAD_HEADER_TYPE_FLAKESIZE_BYTES, BLFS_HEAD_HEADER_BYTES_FLAKESIZE_BYTES },
    { BLFS_HEAD_HEADER_TYPE_INITIALIZED, BLFS_HEAD_HEADER_BYTES_INITIALIZED },
    { BLFS_HEAD_HEADER_TYPE_REKEYING, BLFS_HEAD_HEADER_BYTES_REKEYING }
};

blfs_header_t * blfs_open_header(blfs_backstore_t * backstore, uint32_t header_type)
{
    blfs_header_t * header = malloc(sizeof(blfs_header_t));
    uint64_t offset = 0;

    for(size_t i = 0; i < BLFS_HEAD_NUM_HEADERS; ++i)
    {
        uint32_t const_header_type = header_types_ordered[i][0];
        uint64_t const_header_length = header_types_ordered[i][1];

        if(header_type == const_header_type)
        {
            header->type = header_type;
            header->data_length = const_header_length;
            header->data_offset = offset;

            blfs_backstore_read_head(backstore, header->data, header->data_length, header->data_offset);

            return header;
        }

        offset += const_header_length;
    }

    Throw(EXCEPTION_BAD_HEADER_TYPE);
    return NULL;
}

void blfs_commit_header(blfs_backstore_t * backstore, const blfs_header_t * header)
{
    (void) backstore;
    (void) header;

    bitmask_t * bitmask = bitmask_init(256);
}

void blfs_close_header(blfs_backstore_t * backstore, blfs_header_t * header)
{
    (void) backstore;
    (void) header;
}

blfs_keycount_t * blfs_open_keycount(blfs_backstore_t * backstore, uint64_t nugget_index)
{
    (void) backstore;
    (void) nugget_index;

    return NULL;
}

void blfs_commit_keycount(blfs_backstore_t * backstore, const blfs_keycount_t * count)
{
    (void) backstore;
    (void) count;
}

void blfs_close_keycount(blfs_backstore_t * backstore, blfs_keycount_t * count)
{
    (void) backstore;
    (void) count;
}

blfs_tjournal_entry_t * blfs_open_journal_entry(blfs_backstore_t * backstore, uint64_t nugget_index)
{
    (void) backstore;
    (void) nugget_index;
    
    return NULL;
}

void blfs_commit_journal_entry(blfs_backstore_t * backstore, const blfs_tjournal_entry_t * entry)
{
    (void) backstore;
    (void) entry;
}

void blfs_close_journal_entry(blfs_backstore_t * backstore, blfs_tjournal_entry_t * entry)
{
    (void) backstore;
    (void) entry;
}
