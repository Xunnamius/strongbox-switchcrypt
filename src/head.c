/*
 * <description>
 *
 * @author Bernard Dickens
 */

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "head.h"

blfs_header_t * blfs_open_header(blfs_backstore_t * backstore, uint32_t header_type)
{
    return NULL;
}

void blfs_commit_header(blfs_backstore_t * backstore, const blfs_header_t * header)
{

}

void blfs_close_header(blfs_backstore_t * backstore, blfs_header_t * header)
{

}

blfs_keycount_t * blfs_open_keycount(blfs_backstore_t * backstore, uint64_t nugget_index)
{
    return NULL;
}

void blfs_commit_keycount(blfs_backstore_t * backstore, const blfs_keycount_t * count)
{

}

void blfs_close_keycount(blfs_backstore_t * backstore, blfs_keycount_t * count)
{

}

blfs_tjournal_entry_t * blfs_open_journal_entry(blfs_backstore_t * backstore, uint64_t nugget_index)
{
    return NULL;
}

void blfs_commit_journal_entry(blfs_backstore_t * backstore, const blfs_tjournal_entry_t * entry)
{

}

void blfs_close_journal_entry(blfs_backstore_t * backstore, blfs_tjournal_entry_t * entry)
{

}
