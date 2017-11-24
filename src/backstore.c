/*
 * <description>
 *
 * @author Bernard Dickens
 */

#include "io.h"
#include "backstore.h"

#include <assert.h>
#include <inttypes.h>
#include <unistd.h>

static blfs_header_t * blfs_generate_header_actual(blfs_backstore_t * backstore,
                                                   uint32_t header_type,
                                                   void(*data_handle)(blfs_backstore_t *, blfs_header_t *))
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    blfs_header_t * header = malloc(sizeof(blfs_header_t));

    if(header == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    uint64_t offset = 0;

    for(size_t i = 0; i < BLFS_HEAD_NUM_HEADERS; ++i)
    {
        uint32_t const_header_type   = header_types_ordered[i][0];
        uint64_t const_header_length = header_types_ordered[i][1];
        const char * const_header_name   = header_types_named[i];

        if(header_type == const_header_type)
        {
            header->name = const_header_name;
            header->type = header_type;
            header->data_length = const_header_length;
            header->data_offset = offset;

            header->data = malloc(header->data_length * sizeof(uint8_t));

            if(header->data == NULL)
                Throw(EXCEPTION_ALLOC_FAILURE);

            data_handle(backstore, header);

            IFDEBUG(dzlog_debug("generating blfs_header_t header object"));
            IFDEBUG(dzlog_debug("header->name = %s", header->name));
            IFDEBUG(dzlog_debug("header->type = %"PRIu32, header->type));
            IFDEBUG(dzlog_debug("header->data_length = %"PRIu64, header->data_length));
            IFDEBUG(dzlog_debug("header->data_offset = %"PRIu64, header->data_offset));
            IFDEBUG(dzlog_debug("header->data:"));
            IFDEBUG(hdzlog_debug(header->data, header->data_length));

            KHASH_CACHE_PUT(BLFS_KHASH_HEADERS_CACHE_NAME, backstore->cache_headers, header->type, header);

            IFDEBUG(dzlog_debug("header type %i (%s) was added to the cache", header_type, const_header_name));
            IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
            return header;
        }

        IFDEBUG(uint64_t original_offset = offset);
        offset += const_header_length;
        IFDEBUG(dzlog_debug("offset += %"PRIu64" (was %"PRIu64", now %"PRIu64")", const_header_length, original_offset, offset));
    }

    IFDEBUG(dzlog_error("EXCEPTION: header type %i was not found!", header_type));
    Throw(EXCEPTION_BAD_HEADER_TYPE);

    return NULL;
}

blfs_header_t * blfs_create_header(blfs_backstore_t * backstore, uint32_t header_type, uint8_t * data)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    if(KHASH_CACHE_EXISTS(BLFS_KHASH_HEADERS_CACHE_NAME, backstore->cache_headers, header_type))
    {
        IFDEBUG(dzlog_error("EXCEPTION: tried to create header %i when it already exists in the cache", header_type));
        Throw(EXCEPTION_INVALID_OPERATION);
    }

    IFDEBUG(dzlog_debug("<creating new blfs_header_t header object>"));

    blfs_header_t * header = blfs_generate_header_actual(
        backstore,
        header_type,
        // cppcheck-suppress uninitvar
        LAMBDA(void, (blfs_backstore_t * backstore, blfs_header_t * header)
               { (void) backstore; memcpy(header->data, data, header->data_length); }
        )
    );

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return header;
}

blfs_header_t * blfs_open_header(blfs_backstore_t * backstore, uint32_t header_type)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    khint64_t khash_itr_key;

    if((khash_itr_key = KHASH_CACHE_EXISTS(BLFS_KHASH_HEADERS_CACHE_NAME, backstore->cache_headers, header_type)))
    {
        blfs_header_t * cached = KHASH_CACHE_GET_WITH_ITRP1(backstore->cache_headers, khash_itr_key);
        IFDEBUG(dzlog_debug("CACHE HIT: header type %i (%s) was found in the cache", header_type, cached->name));
        IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
        return cached;
    }

    IFDEBUG(dzlog_debug("header type %i (human readable name found below) was not found in the cache", header_type));

    IFDEBUG(dzlog_debug("<opening blfs_header_t header object>"));

    blfs_header_t * header = blfs_generate_header_actual(
        backstore,
        header_type,
        // cppcheck-suppress uninitvar
        // cppcheck-suppress uninitStructMember
        LAMBDA(void, (blfs_backstore_t * backstore, blfs_header_t * header)
            { blfs_backstore_read(backstore, header->data, header->data_length, header->data_offset); }
        )
    );

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return header;
}

void blfs_commit_header(blfs_backstore_t * backstore, const blfs_header_t * header)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    blfs_backstore_write(backstore, header->data, header->data_length, header->data_offset);

    IFDEBUG(dzlog_debug("committed header data to backstore:"));
    IFDEBUG(dzlog_debug("header->name = %s", header->name));
    IFDEBUG(dzlog_debug("header->type = %"PRIu32, header->type));
    IFDEBUG(dzlog_debug("header->data_length = %"PRIu64, header->data_length));
    IFDEBUG(dzlog_debug("header->data_offset = %"PRIu64, header->data_offset));
    IFDEBUG(dzlog_debug("header->data:"));
    IFDEBUG(hdzlog_debug(header->data, header->data_length));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_close_header(blfs_backstore_t * backstore, blfs_header_t * header)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    khint64_t khash_itr_key;

    if((khash_itr_key = KHASH_CACHE_EXISTS(BLFS_KHASH_HEADERS_CACHE_NAME, backstore->cache_headers, header->type)))
    {
        IFDEBUG(dzlog_debug("CACHE HIT: header type %i (%s) was deleted from the cache", header->type, header->name));
        KHASH_CACHE_DEL_WITH_ITRP1(BLFS_KHASH_HEADERS_CACHE_NAME, backstore->cache_headers, khash_itr_key);
    }

    IFDEBUG(dzlog_debug("header type %i (%s) is about to be freed...", header->type, header->name));

    free(header->data);
    free(header);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_commit_all_headers(blfs_backstore_t * backstore)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    for(size_t i = 0; i < BLFS_HEAD_NUM_HEADERS; ++i)
    {
        uint32_t header_type = header_types_ordered[i][0];

        if(header_type == BLFS_HEAD_HEADER_TYPE_INITIALIZED)
            continue;

        blfs_commit_header(backstore, blfs_open_header(backstore, header_type));
    }
    
    blfs_commit_header(backstore, blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_INITIALIZED));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

blfs_keycount_t * blfs_create_keycount(blfs_backstore_t * backstore, uint64_t nugget_index)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    if(KHASH_CACHE_EXISTS(BLFS_KHASH_KCS_CACHE_NAME, backstore->cache_kcs_counts, nugget_index))
    {
        IFDEBUG(dzlog_error("EXCEPTION: tried to create keycount %"PRIu64" when it already exists in the cache", nugget_index));
        Throw(EXCEPTION_INVALID_OPERATION);
    }

    blfs_keycount_t * count = malloc(sizeof(blfs_keycount_t));

    if(count == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    count->nugget_index = nugget_index;
    count->data_offset = backstore->kcs_real_offset + nugget_index * BLFS_HEAD_BYTES_KEYCOUNT;
    count->data_length = BLFS_HEAD_BYTES_KEYCOUNT;
    count->keycount = 0;

    IFDEBUG(dzlog_debug("created new keycount object"));
    IFDEBUG(dzlog_debug("backstore->kcs_real_offset = %"PRIu64, backstore->kcs_real_offset));
    IFDEBUG(dzlog_debug("count->nugget_index = %"PRIu32, count->nugget_index));
    IFDEBUG(dzlog_debug("count->data_offset = %"PRIu64, count->data_offset));
    IFDEBUG(dzlog_debug("count->data_length = %"PRIu64, count->data_length));
    IFDEBUG(dzlog_debug("count->keycount = %"PRIu64, count->keycount));

    KHASH_CACHE_PUT(BLFS_KHASH_KCS_CACHE_NAME, backstore->cache_kcs_counts, nugget_index, count);

    IFDEBUG(dzlog_debug("keycount for nugget id %"PRIu64" was added to the cache", nugget_index));
    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));

    return count;
}

blfs_keycount_t * blfs_open_keycount(blfs_backstore_t * backstore, uint64_t nugget_index)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    blfs_keycount_t * count;
    khint64_t khash_itr_key;

    if((khash_itr_key = KHASH_CACHE_EXISTS(BLFS_KHASH_KCS_CACHE_NAME, backstore->cache_kcs_counts, nugget_index)))
    {
        count = KHASH_CACHE_GET_WITH_ITRP1(backstore->cache_kcs_counts, khash_itr_key);
        IFDEBUG(dzlog_debug("CACHE HIT: keycount for nugget id %"PRIu64" was found in the cache", nugget_index));
    }

    else
    {
        IFDEBUG(dzlog_debug("keycount for nugget id %"PRIu64" was not found in the cache", nugget_index));

        count = malloc(sizeof(blfs_keycount_t));

        if(count == NULL)
            Throw(EXCEPTION_ALLOC_FAILURE);

        count->nugget_index = nugget_index;
        count->data_offset = backstore->kcs_real_offset + nugget_index * BLFS_HEAD_BYTES_KEYCOUNT;
        count->data_length = BLFS_HEAD_BYTES_KEYCOUNT;

        uint8_t count_data[count->data_length];
        blfs_backstore_read(backstore, count_data, count->data_length, count->data_offset);

        memcpy(&(count->keycount), count_data, count->data_length);

        IFDEBUG(dzlog_debug("opened blfs_keycount_t count object"));
        IFDEBUG(dzlog_debug("backstore->kcs_real_offset = %"PRIu64, backstore->kcs_real_offset));
        IFDEBUG(dzlog_debug("count->nugget_index = %"PRIu32, count->nugget_index));
        IFDEBUG(dzlog_debug("count->data_offset = %"PRIu64, count->data_offset));
        IFDEBUG(dzlog_debug("count->data_length = %"PRIu64, count->data_length));
        IFDEBUG(dzlog_debug("count->keycount = %"PRIu64, count->keycount));
        IFDEBUG(dzlog_debug("count->keycount (as data):"));
        IFDEBUG(hdzlog_debug(&(count->keycount), count->data_length));

        KHASH_CACHE_PUT(BLFS_KHASH_KCS_CACHE_NAME, backstore->cache_kcs_counts, nugget_index, count);

        IFDEBUG(dzlog_debug("keycount for nugget id %"PRIu64" was added to the cache", nugget_index));
    }

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return count;
}

void blfs_commit_keycount(blfs_backstore_t * backstore, const blfs_keycount_t * count)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    blfs_backstore_write(backstore, (uint8_t *) &(count->keycount), count->data_length, count->data_offset);

    IFDEBUG(dzlog_debug("committed keycount data to backstore:"));
    IFDEBUG(dzlog_debug("count->nugget_index = %"PRIu32, count->nugget_index));
    IFDEBUG(dzlog_debug("count->data_length = %"PRIu64, count->data_length));
    IFDEBUG(dzlog_debug("count->data_offset = %"PRIu64, count->data_offset));
    IFDEBUG(dzlog_debug("count->keycount = %"PRIu64, count->keycount));
    IFDEBUG(dzlog_debug("count->keycount (as data):"));
    IFDEBUG(hdzlog_debug((uint8_t *) &(count->keycount), count->data_length));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_close_keycount(blfs_backstore_t * backstore, blfs_keycount_t * count)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    khint64_t khash_itr_key;

    if((khash_itr_key = KHASH_CACHE_EXISTS(BLFS_KHASH_KCS_CACHE_NAME, backstore->cache_kcs_counts, count->nugget_index)))
    {
        IFDEBUG(dzlog_debug("CACHE HIT: keycount for nugget id %"PRIu32" was deleted from the cache", count->nugget_index));
        KHASH_CACHE_DEL_WITH_ITRP1(BLFS_KHASH_KCS_CACHE_NAME, backstore->cache_kcs_counts, khash_itr_key);
    }

    IFDEBUG(dzlog_debug("keycount for nugget id %"PRIu32" is about to be freed...", count->nugget_index));

    free(count);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

blfs_tjournal_entry_t * blfs_create_tjournal_entry(blfs_backstore_t * backstore, uint64_t nugget_index)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    if(KHASH_CACHE_EXISTS(BLFS_KHASH_TJ_CACHE_NAME, backstore->cache_tj_entries, nugget_index))
    {
        IFDEBUG(dzlog_error("EXCEPTION: tried to create transaction journal entry %"PRIu64" when it already exists in the cache", nugget_index));
        Throw(EXCEPTION_INVALID_OPERATION);
    }

    blfs_tjournal_entry_t * entry = malloc(sizeof(blfs_tjournal_entry_t));

    if(entry == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    IFDEBUG(dzlog_debug("backstore->flakes_per_nugget = %"PRIu32, backstore->flakes_per_nugget));

    entry->nugget_index = nugget_index;
    entry->data_length = CEIL(backstore->flakes_per_nugget, BITS_IN_A_BYTE);
    entry->data_offset = backstore->tj_real_offset + nugget_index * entry->data_length;

    IFDEBUG(dzlog_debug("created new blfs_tjournal_entry_t entry object"));
    IFDEBUG(dzlog_debug("backstore->tj_real_offset = %"PRIu64, backstore->tj_real_offset));
    IFDEBUG(dzlog_debug("entry->nugget_index = %"PRIu32, entry->nugget_index));
    IFDEBUG(dzlog_debug("entry->data_offset = %"PRIu64, entry->data_offset));
    IFDEBUG(dzlog_debug("entry->data_length = %"PRIu64, entry->data_length));

    entry->bitmask = bitmask_init(NULL, entry->data_length);

    KHASH_CACHE_PUT(BLFS_KHASH_TJ_CACHE_NAME, backstore->cache_tj_entries, nugget_index, entry);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return entry;
}

blfs_tjournal_entry_t * blfs_open_tjournal_entry(blfs_backstore_t * backstore, uint64_t nugget_index)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    blfs_tjournal_entry_t * entry;
    khint64_t khash_itr_key;

    if((khash_itr_key = KHASH_CACHE_EXISTS(BLFS_KHASH_TJ_CACHE_NAME, backstore->cache_tj_entries, nugget_index)))
    {
        IFDEBUG(dzlog_debug("CACHE HIT: transaction journal entry for nugget id %"PRIu64" was found in the cache", nugget_index));
        entry = KHASH_CACHE_GET_WITH_ITRP1(backstore->cache_tj_entries, khash_itr_key);
    }

    else
    {
        IFDEBUG(dzlog_debug("transaction journal entry for nugget id %"PRIu64" was not found in the cache", nugget_index));

        entry = malloc(sizeof(blfs_tjournal_entry_t));

        if(entry == NULL)
            Throw(EXCEPTION_ALLOC_FAILURE);

        IFDEBUG(dzlog_debug("backstore->flakes_per_nugget = %"PRIu32, backstore->flakes_per_nugget));

        entry->nugget_index = nugget_index;
        entry->data_length = CEIL(backstore->flakes_per_nugget, BITS_IN_A_BYTE);
        entry->data_offset = backstore->tj_real_offset + nugget_index * entry->data_length;

        IFDEBUG(dzlog_debug("opened blfs_tjournal_entry_t entry object"));
        IFDEBUG(dzlog_debug("backstore->tj_real_offset = %"PRIu64, backstore->tj_real_offset));
        IFDEBUG(dzlog_debug("entry->nugget_index = %"PRIu32, entry->nugget_index));
        IFDEBUG(dzlog_debug("entry->data_offset = %"PRIu64, entry->data_offset));
        IFDEBUG(dzlog_debug("entry->data_length = %"PRIu64, entry->data_length));

        uint8_t mask_data[entry->data_length];

        blfs_backstore_read(backstore, mask_data, entry->data_length, entry->data_offset);
        entry->bitmask = bitmask_init(mask_data, entry->data_length);

        KHASH_CACHE_PUT(BLFS_KHASH_TJ_CACHE_NAME, backstore->cache_tj_entries, nugget_index, entry);

        IFDEBUG(dzlog_debug("transaction journal entry for nugget id %"PRIu64" was added to the cache", nugget_index));
    }

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return entry;
}

void blfs_commit_tjournal_entry(blfs_backstore_t * backstore, const blfs_tjournal_entry_t * entry)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    IFDEBUG(dzlog_debug("committing transaction journal entry data to backstore:"));
    IFDEBUG(dzlog_debug("entry->nugget_index = %"PRIu32, entry->nugget_index));
    IFDEBUG(dzlog_debug("entry->data_length (should match below)          = %"PRIu64, entry->data_length));
    IFDEBUG(dzlog_debug("entry->bitmask->byte_length (should match above) = %zu", entry->bitmask->byte_length));
    IFDEBUG(dzlog_debug("entry->data_offset = %"PRIu64, entry->data_offset));
    IFDEBUG(dzlog_debug("entry->bitmask (as data):"));
    IFDEBUG(hdzlog_debug(entry->bitmask->mask, entry->bitmask->byte_length));

    assert(entry->data_length == entry->bitmask->byte_length);
    blfs_backstore_write(backstore, entry->bitmask->mask, entry->bitmask->byte_length, entry->data_offset);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_close_tjournal_entry(blfs_backstore_t * backstore, blfs_tjournal_entry_t * entry)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    khint64_t khash_itr_key;

    if((khash_itr_key = KHASH_CACHE_EXISTS(BLFS_KHASH_TJ_CACHE_NAME, backstore->cache_tj_entries, entry->nugget_index)))
    {
        IFDEBUG(dzlog_debug(
            "CACHE HIT: transaction journal entry for nugget id %"PRIu32" was deleted from the cache", entry->nugget_index));
        KHASH_CACHE_DEL_WITH_ITRP1(BLFS_KHASH_TJ_CACHE_NAME, backstore->cache_tj_entries, khash_itr_key);
    }

    IFDEBUG(dzlog_debug("transaction journal entry for nugget id %"PRIu32" is about to be freed...", entry->nugget_index));

    bitmask_fini(entry->bitmask);
    free(entry);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_fetch_journaled_data(blfs_backstore_t * backstore,
                               uint64_t rekeying_nugget_index,
                               blfs_keycount_t * rekeying_count,
                               blfs_tjournal_entry_t * rekeying_entry,
                               uint8_t * rekeying_nugget_data)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    blfs_keycount_t * jcount = malloc(sizeof(*jcount));
    blfs_tjournal_entry_t * jentry = malloc(sizeof(*jentry));

    if(jcount == NULL || jentry == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    IFDEBUG(dzlog_debug("backstore->kcs_journaled_offset = %"PRIu64, backstore->kcs_journaled_offset));
    IFDEBUG(dzlog_debug("backstore->tj_journaled_offset = %"PRIu64, backstore->tj_journaled_offset));
    IFDEBUG(dzlog_debug("backstore->nugget_journaled_offset = %"PRIu64, backstore->nugget_journaled_offset));

    // Set up jcount

    jcount->nugget_index = rekeying_nugget_index;
    jcount->data_length = BLFS_HEAD_BYTES_KEYCOUNT;
    jcount->data_offset = backstore->kcs_journaled_offset;

    uint8_t jcount_data[jcount->data_length];

    blfs_backstore_read(backstore, jcount_data, jcount->data_length, jcount->data_offset);

    memcpy(&(jcount->keycount), jcount_data, jcount->data_length);

    IFDEBUG(dzlog_debug("opened blfs_keycount_t *journaled* count object"));
    IFDEBUG(dzlog_debug("jcount->nugget_index = %"PRIu32, jcount->nugget_index));
    IFDEBUG(dzlog_debug("jcount->data_offset = %"PRIu64, jcount->data_offset));
    IFDEBUG(dzlog_debug("jcount->data_length = %"PRIu64, jcount->data_length));
    IFDEBUG(dzlog_debug("jcount->keycount = %"PRIu64, jcount->keycount));
    IFDEBUG(dzlog_debug("jcount->keycount (as data):"));
    IFDEBUG(hdzlog_debug(&(jcount->keycount), jcount->data_length));

    // Set up jentry

    jentry->nugget_index = rekeying_nugget_index;
    jentry->data_length = backstore->nugget_journaled_offset - backstore->tj_journaled_offset;
    jentry->data_offset = backstore->tj_journaled_offset;

    IFDEBUG(dzlog_debug("opened blfs_tjournal_entry_t *journaled* entry object"));
    IFDEBUG(dzlog_debug("jentry->nugget_index = %"PRIu32, jentry->nugget_index));
    IFDEBUG(dzlog_debug("jentry->data_offset = %"PRIu64, jentry->data_offset));
    IFDEBUG(dzlog_debug("jentry->data_length = %"PRIu64, jentry->data_length));

    uint8_t mask_data[jentry->data_length];

    blfs_backstore_read(backstore, mask_data, jentry->data_length, jentry->data_offset);
    jentry->bitmask = bitmask_init(mask_data, jentry->data_length);

    // Set up journaled nugget data

    blfs_backstore_read(backstore, rekeying_nugget_data, backstore->nugget_size_bytes, backstore->nugget_journaled_offset);

    // Finish up

    memcpy(rekeying_count, jcount, sizeof(*jcount));
    memcpy(rekeying_entry, jentry, sizeof(*jentry));

    free(jcount);
    free(jentry);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}
