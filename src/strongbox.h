#ifndef BLFS_BUSELFS_H_
#define BLFS_BUSELFS_H_

#include "constants.h"
#include "backstore.h"
#include "buse.h"
#include "io.h"
#include "crypto.h"
#include "mmc.h"
#include "khash.h"
#include "merkletree.h"
#include "swappable.h"

#include <mqueue.h>

typedef struct blfs_swappable_cipher_t blfs_swappable_cipher_t;
typedef struct buselfs_state_t buselfs_state_t;
typedef struct blfs_mq_msg_t blfs_mq_msg_t;

KHASH_MAP_INIT_STR(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, uint8_t *)

/**
 * This struct represents program state and is passed around to various
 * StrongBox functions.
 *
 * The main use of this state object is to assist in proper unit testing.
 */
typedef struct buselfs_state_t
{
    /**
     * The backstore used by the StrongBox software.
     */
    blfs_backstore_t * backstore;

    /**
     * A cache that holds each of the keys for every nugget and flake in the
     * filesystem.
     *
     * ?? Keys look like:
     * * nugget keys: nugget_index
     * *  => master_secret+nugget_index
     * * flake keys: nugget_index||flake_id||associated_keycount
     * *  => master_secret+nugget_index+flake_id+associated_keycount
     *
     * ! This uses quite a bit of memory
     *
     * ! strdup() is used to persist keys; could be a memory leak location if
     * ! not careful. Watch out!
     */
    khash_t(BLFS_KHASH_NUGGET_KEY_CACHE_NAME) * cache_nugget_keys;

    /**
     * The Merkle Tree that ensures integrity protection. Leaves are legion.
     *
     * ?? General structure (n=nugget count, fpn=flakes/nugget):
     *
     * ? TPM global version:
     * *    index 0
     * ? Headers (excluding TPMGV, INITIALIZED and MTRH):
     * *    index [1, BLFS_HEAD_NUM_HEADERS-3]
     * ? Keycounts:
     * *    index [BLFS_HEAD_NUM_HEADERS-2, n+(BLFS_HEAD_NUM_HEADERS-3)]
     * ? Transaction journal entries:
     * *    index [n+(BLFS_HEAD_NUM_HEADERS-2), 2*n+(BLFS_HEAD_NUM_HEADERS-3)]
     * ? Nugget metadata structs:
     * *    index [2*n+(BLFS_HEAD_NUM_HEADERS-2), 2*n+(BLFS_HEAD_NUM_HEADERS-3)+(n*fpn)]
     * ? Flake poly1305 tags:
     * *    index [2*n+(BLFS_HEAD_NUM_HEADERS-2)+(n*fpn), 2*n+(BLFS_HEAD_NUM_HEADERS-3)+(2*n*fpn)]
     *
     * ?? As of version 500, with (n=3, fpn=2), this structure yields:
     * * 0 [1, 6] [7, 9] [10, 12] [13, 18] [19, 24]
     *
     * ? Total (since it's zero index) = 2*n+(BLFS_HEAD_NUM_HEADERS-3)+(2*n*fpn)+1
     *
     * See mt_calculate_expected_size() for exact calculation
     */
    mt_t * merkle_tree;
    mt_hash_t merkle_tree_root_hash;

    /**
     * If not null, this default password should be used and the user should not
     * be disturbed. Useful for unit testing.
     */
    char * default_password;

    /**
     * This stores the primary cipher context. See swappable.h for details.
     */
    blfs_swappable_cipher_t * primary_cipher;

    /**
     * This stores the swap cipher context. See swappable.h for details.
     */
    blfs_swappable_cipher_t * swap_cipher;

    /**
     * This is the id of the currently active available cipher context.
     */
    swappable_cipher_e active_cipher_enum_id;

    /**
     * This stores the currently active swap strategy. See swappable.h for
     * details.
     */
    swap_strategy_e active_swap_strategy;

    /**
     * This stores the currently active usecase. See swappable.h for details.
     */
    usecase_e active_usecase;

    /**
     * If we're in crash recover mode (TRUE) or not (FALSE). If we are, then
     * all rekeying efforts must increment the keycount store entries by +2
     * instead of +1 to avoid any unpleasantness.
     */
    int crash_recovery;

    /**
     * Index of the RPMB counter block in the RPMB space
     */
    uint64_t rpmb_secure_index;

    /**
     * The message queue descriptor pointing to the queue storing all incoming
     * messages
     */
    mqd_t qd_incoming;

    /**
     * The message queue descriptor pointing to the queue storing all outgoing
     * messages
     *
     * ! Note: in a real implementation, this would be client-process-specific
     */
    mqd_t qd_outgoing;

    /**
     * Allows the entire system to know if cipher switching is happening. Useful
     * for internal debugging purposes.
     */
    int is_cipher_swapping;

    /**
     * struct buse_operations buseops is required by the BUSE subsystem. It is
     * very similar to its FUSE counterpart in intent.
     */
    struct buse_operations * buseops;

    /**
     * If non-zero, reads and writes will have a latency penalty of
     * BLFS_DELAY_RW_PENALTY_MS milliseconds (StrongBox will sleep)
     */
    int delay_rw;
} buselfs_state_t;

/**
 * This struct describes a POSIX message queue message to StrongBox. Messages
 * consist of an opcode and a payload for data. This format is used for both
 * incoming and outgoing communications with the queue.
 */
typedef struct blfs_mq_msg_t
{
    /**
     * The 1-byte opcode represents one of 255 possible operations to be
     * performed in response to this message being received. See
     * update_application_state_check_mq for those responses and their opcodes.
     * Note that an opcode of 0 indicates an error/null message!
     */
    uint8_t opcode;

    /**
     * Unimplemented. //TODO (low priority)
     */
    uint8_t priority;

    /**
     * This (BLFS_SV_MESSAGE_SIZE_BYTES - 1) byte payload of data that
     * accompanies the operation described above. Might be empty.
     */
    uint8_t payload[BLFS_SV_MESSAGE_SIZE_BYTES - 1];
} blfs_mq_msg_t;

/**
 * Add a nugget_index => nugget_key pair to the key cache if it is active. If
 * the key cache is disabled, this is a noop.
 *
 * ! These caches grow, but they never shrink, even though they DEFINITELY
 * ! should during rekeying. This is a memory leak. To be fixed eventually (so
 * ! never).
 */
void add_index_to_key_cache(buselfs_state_t * buselfs_state, uint32_t nugget_index, uint8_t * nugget_key);

/**
 * Add a nugget_index (keychain) => nugget_key pair to the key cache if it is
 * active. A keychain is a key consisting of a chain of data, e.g.
 * nugget_index||flake_index "chained" together. If the key cache is disabled,
 * this is a noop.
 */
void add_keychain_to_key_cache(buselfs_state_t * buselfs_state,
                               uint32_t nugget_index,
                               uint32_t flake_index,
                               uint64_t keycount,
                               uint8_t * flake_key);

/**
 * Get a nugget_index => nugget_key pair from the key cache if it is active. If
 * the key cache is disabled, this is a noop.
 */
void get_nugget_key_using_index(uint8_t * nugget_key, buselfs_state_t * buselfs_state, uint32_t nugget_index);

/**
 * Get a nugget_index (keychain) => nugget_key pair from the key cache if it is
 * active. A keychain is a key consisting of a chain of data, e.g.
 * nugget_index||flake_index "chained" together. If the key cache is disabled,
 * this is a noop.
 */
void get_flake_key_using_keychain(uint8_t * flake_key,
                                  const buselfs_state_t * buselfs_state,
                                  uint32_t nugget_index,
                                  uint32_t flake_index,
                                  uint64_t keycount);

/**
 * Update the global merkle tree root hash
 *
 * ! This function MUST be called before buselfs_state->merkle_tree_root_hash
 * ! is referenced!
 */
void update_merkle_tree_root_hash(buselfs_state_t * buselfs_state);

/**
 * Commit the global merkle tree root hash to the backing store
 */
void commit_merkle_tree_root_hash(buselfs_state_t * buselfs_state);

/**
 * Add a leaf to the global merkle tree
 */
void add_to_merkle_tree(uint8_t * data, size_t length, const buselfs_state_t * buselfs_state);

/**
 * Update a leaf in the global merkle tree
 */
void update_in_merkle_tree(uint8_t * data, size_t length, uint32_t index, const buselfs_state_t * buselfs_state);

/**
 * Verify a leaf in the global merkle tree
 */
void verify_in_merkle_tree(uint8_t * data, size_t length, uint32_t index, const buselfs_state_t * buselfs_state);

/**
 * Calculates the total space required to store one nugget and its associated
 * metadata and header data. This has been abstracted out to make it easier to
 * add deep changes to the StrongBox internals (e.g. extra n-dependent storage
 * layers).
 */
uint32_t calculate_total_space_required_for_1nug(uint32_t nuggetsize, uint32_t flakes_per_nugget, uint32_t md_bytes_per_nugget);

/**
 * Calculates the expected size of the merkle tree after it's been initially
 * populated. This has been abstracted out to make it easier to add deep changes
 * to the StrongBox internals (e.g. extra n-dependent storage layers).
 *
 * ? For example:
 * * mt_calculate_expected_size(total_number_of_nuggets, buselfs_state)
 * ? would return the total size of the entire merkle tree after initial
 * ? population!
 *
 * @nugget_index This function will count nuggets up to BUT EXCLUDING this index
 */
uint32_t mt_calculate_expected_size(const buselfs_state_t * buselfs_state, uint32_t nugget_index);

/**
 * Calculates the offset of a flake in the merkle tree. This has been abstracted
 * out to make it easier to add deep changes to the StrongBox internals (e.g.
 * extra n-dependent storage layers).
 */
uint32_t mt_calculate_flake_offset(const buselfs_state_t * buselfs_state, uint32_t jump_to_nugget_index, uint32_t flake_index);

/* Similar functions to the above */
uint32_t mt_calculate_metadata_mt_index(const buselfs_state_t * buselfs_state, uint32_t nugget_index);
uint32_t mt_calculate_tj1_index(const buselfs_state_t * buselfs_state, uint32_t nugget_index);
uint32_t mt_calculate_keycount_index(uint32_t nugget_index);

// ? Note: you may be wondering why the main file has been broken up like this.
// ?
// ? The answer is simple: unit testing. One cannot unit test a big fat main
// ? function in any pleasing way. Comes with free organizational boons, too!

/**
 * BUSE read operation handler. Passed directly to the buse core. See buse
 * documentation for more information.
 *
 * @param  userdata (buselfs_state*)
 */
int buse_read(void * buffer, uint32_t len, uint64_t offset, void * userdata);

/**
 * BUSE write operation handler. Passed directly to the buse core. See buse
 * documentation for more information.
 *
 * @param  userdata (buselfs_state*)
 */
int buse_write(const void * buffer, uint32_t len, uint64_t offset, void * userdata);

/**
 * Sugar function wrapping blfs_backstore_open that handles updating
 * md_bytes_per_nugget at the correct point and with context (buselfs_state).
 */
blfs_backstore_t * blfs_backstore_open_with_ctx(const char * path, buselfs_state_t * buselfs_state);

/**
 * Wrapper around the POSIX message queue functions that initializes the queues
 * StrongBox expects to exist. This function should only be called once during
 * initialization. `buselfs_state` need not be fully intialized at the point
 * this function is called.
 *
 * ! Note that the message queue descriptors should be closed after use, which
 * ! the StrongBox API does not do for you (or ever)!
 */
void blfs_initialize_queues(buselfs_state_t * buselfs_state);

/**
 * Clears all messages from StrongBox's incoming queue. Useful after
 * initialization to prevent residue from other runs from effecting this
 * instance.
 */
void blfs_clear_incoming_queue(buselfs_state_t * buselfs_state);

/**
 * Wrapper around the POSIX message queue open function. Set `incoming_outgoing`
 * to 0 for incoming or 1 for outgoing (determines permissions/open mode).
 */
mqd_t blfs_open_queue(char * queue_name, int incoming_outgoing);

/**
 * Wrapper around the POSIX message queue read function that checks the input
 * queue for new items, returning as quickly as possible. This function is
 * suitable to be called in time sensitive contexts (such as within buse
 * read/write functions). `message.opcode = 0` indicates the queue was empty.
 */
void blfs_read_input_queue(buselfs_state_t * buselfs_state, blfs_mq_msg_t * message);

/**
 * Wrapper around the POSIX message queue read function that pushes new items
 * onto the output queue, returning as quickly as possible. This function is
 * suitable to be called in time sensitive contexts (such as within buse
 * read/write functions). `message.opcode` must be between 1 and 255. `priority`
 * must be between 0 and the system maximum (usually ~30k).
 */
void blfs_write_output_queue(buselfs_state_t * buselfs_state, blfs_mq_msg_t * message, unsigned int priority);

/**
 * Checks the well-defined POSIX message queue for any updates from the world
 * and updates the application state accordingly (e.g. cipher switching logic is
 * here)
 */
void update_application_state_check_mq(buselfs_state_t * buselfs_state);

/**
 * Implementation of the StrongBox rekeying procedure for on-write overwrite
 * attempts. Re-encrypts a nugget with an entirely different key, performing an
 * in-memory overwrite before writeback, and updates the cache accordingly. This
 * is called when an overwrite occurs during buse_write().
 */
void blfs_rekey_nugget_then_write(buselfs_state_t * buselfs_state,
                                  uint32_t rekeying_nugget_id,
                                  const uint8_t * buffer,
                                  uint32_t length,
                                  uint64_t nugget_internal_offset);

int blfs_swap_nugget_to_active_cipher(int swapping_while_read_or_write,
                                      int on_last_nugget,
                                      buselfs_state_t * buselfs_state,
                                      uint64_t target_nugget_index,
                                      uint8_t * buffer,
                                      uint32_t buffer_length,
                                      uint64_t nugget_internal_offset);

/**
 * Open a backstore and perform initial validation checks and asserts.
 */
void blfs_soft_open(buselfs_state_t * buselfs_state, uint8_t cin_allow_insecure_start);

/**
 * Implementation of the CREATE command mode.
 */
void blfs_run_mode_create(const char * backstore_path,
                          uint64_t cin_backstore_size,
                          uint32_t cin_flake_size,
                          uint32_t cin_flakes_per_nugget,
                          buselfs_state_t * buselfs_state);

/**
 * Implementation of the OPEN command mode.
 */
void blfs_run_mode_open(const char * backstore_path, uint8_t cin_allow_insecure_start, buselfs_state_t * buselfs_state);

/**
 * Implementation of the WIPE command mode.
 */
void blfs_run_mode_wipe(const char * backstore_path, uint8_t cin_allow_insecure_start, buselfs_state_t * buselfs_state);

/**
 * The function that is actually responsible for assembling the disperate
 * pieces that come together to form the functioning StrongBox instance. This
 * function should not be called directly. Call strongbox_main() instead.
 */
buselfs_state_t * strongbox_main_actual(int argc, char * argv[], char * blockdevice);

/**
 * The entry point for the StrongBox software. Call this from main()
 */
int strongbox_main(int argc, char * argv[]);

#endif /* BLFS_BUSELFS_H_ */
