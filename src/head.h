#ifndef HEAD_H
#define HEAD_H

#include <stdint.h>
#include "bitmask.h";
#include "io.h";
#include "head.h";

/**
 * struct buselfs_header
 *
 * @type            HEAD_HEADER_TYPE_*
 * @data_offset     data offset in the backstore
 * @data_length     total length of the nugget in the backstore
 * @data            header value data (in bytes)
 * @backstore       the backstore itself
 * @is_open         if this struct has had its members free()'d (0 = yes)
 */
typedef struct buselfs_header
{
    int type;

    uint64_t data_offset;
    uint64_t data_length;

    char * data;

    buselfs_backstore * backstore;

    char is_open;
} buselfs_header;

/**
 * buselfs_keystore_count
 *
 * @global_id       the global ID that ties keystore, journal, and nugget
 * @data_offset     data offset in the backstore
 * @data_length     total length of the nugget in the backstore
 * @data            extended_bit_mask type header value data (a <=>64 bit mask)
 * @mac_tag         poly1305 mac tag
 * @backstore       the backstore itself
 * @is_open         if this struct has had its members free()'d (0 = yes)
 */
typedef struct buselfs_keystore_count
{
    uint64_t global_id;
    uint64_t data_offset;
    uint64_t data_length;

    extended_bit_mask * data;
    char * mac_tag;

    buselfs_backstore * backstore;

    char is_open;
} buselfs_keystore_count;

/**
 * buselfs_journal_entry
 *
 * @global_id       the global ID that ties keystore, journal, and nugget
 * @data_offset     data offset in the backstore
 * @data_length     total length of the nugget in the backstore
 * @data            header value data (in bytes)
 * @status          journal entry status
 * @mac_tag         poly1305 mac tag
 * @backstore       the backstore itself
 * @is_open         if this struct has had its members free()'d (0 = yes)
 */
typedef struct buselfs_journal_entry
{
    uint64_t global_id;
    uint64_t data_offset;
    uint64_t data_length;

    char * data;
    char * mac_tag;
    unsigned char status;

    buselfs_backstore * backstore;

    char is_open;
} buselfs_journal_entry;

int buselfs_open_header(buselfs_backstore * backstore, int header_type, Header * header);
int buselfs_commit_header(buselfs_header * header);
int buselfs_close_header(buselfs_header * header);
int buselfs_is_fully_initialized(buselfs_backstore * backstore);

int buselfs_open_keystore_count(buselfs_backstore * backstore, int global_id, buselfs_keystore_count * count);
int buselfs_commit_keystore_count(buselfs_keystore_count * count);
int buselfs_close_keystore_count(buselfs_keystore_count * count);
int buselfs_increment_keystore_count(buselfs_keystore_count * count);
int buselfs_verify_keystore_count_tag(buselfs_keystore_count * count);
int buselfs_generate_keystore_count_tag(buselfs_keystore_count * count);

int buselfs_open_journal_entry(buselfs_backstore * backstore, int global_id, buselfs_journal_entry * entry);
int buselfs_commit_journal_entry(buselfs_journal_entry * entry);
int buselfs_close_journal_entry(buselfs_journal_entry * entry);
int buselfs_is_flake_dirty(int flakeIndex, buselfs_journal_entry * entry);
int buselfs_set_flake_dirty(int flakeIndex, buselfs_journal_entry * entry);
int buselfs_verify_journal_entry_tag(buselfs_journal_entry * entry);
int buselfs_generate_journal_entry_tag(buselfs_journal_entry * entry);

#endif /* HEAD_H */
