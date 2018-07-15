#ifndef BLFS_SWAP_H_
#define BLFS_SWAP_H_

#include "constants.h"
#include "strongbox.h"

typedef struct blfs_swappable_cipher_t blfs_swappable_cipher_t;
typedef struct buselfs_state_t buselfs_state_t;

#include "ciphers.h"

// TODO: make the *_handle interfaces expose a more similar and intuitive API

/**
 * This struct defines a common crypt interface for algorithm swapping. Cipher
 * implementations can use either sc_fn_write_handle and sc_fn_read_handle,
 * sc_fn_crypt_data, or sc_fn_crypt_data_custom to control StrongBox's crypt
 * behavior at different levels of abstraction within StrongBox.
 *
 * sc_fn_crypt_data expects your cipher to accept intra- and inter- nugget
 * offset data and return crypted the specified region and so operates at a
 * finegrain level compared to using the read and write handles. There is no
 * distinction made between encryption and decryption as they're considered the
 * same operation in this context. Further, this interface does not allow any
 * access to the StrongBox internals and is expected to execute independently.
 *
 * Unlike sc_fn_crypt_data_custom, sc_fn_crypt_data performs the final XORing
 * for you and gives you a convenient xor buffer to red your crypted data into.
 * As such, it provides a slightly higher level of interaction with the backing
 * store's data making things easier for simpler ciphers.
 */
typedef void (*sc_fn_crypt_data)(
    const blfs_swappable_cipher_t * sc,
    uint64_t interblock_offset,
    uint64_t intrablock_offset,
    uint64_t num_blocks,
    uint64_t zero_str_length,
    uint64_t block_read_upper_bound,
    const uint8_t * nugget_key,
    const uint64_t kcs_keycount,
    const uint8_t * const kcs_keycount_ptr,
    uint8_t * xor_str
);

/**
 * This struct defines a common crypt interface for algorithm swapping. Cipher
 * implementations can use either sc_fn_write_handle and sc_fn_read_handle,
 * sc_fn_crypt_data, or sc_fn_crypt_data_custom to control StrongBox's crypt
 * behavior at different levels of abstraction within StrongBox.
 *
 * sc_fn_crypt_data_custom expects your cipher to accept intra- and inter-
 * nugget offset data and return crypted the specified region, hence operating
 * at a finegrain level compared to using the read and write handles. There is
 * no distinction made between encryption and decryption as they're considered
 * the same operation in this context. Further, this interface does not allow
 * any access to the StrongBox internals and is expected to execute
 * independently.
 *
 * Unlike sc_fn_crypt_data, sc_fn_crypt_data_custom does not perform the final
 * XORing for you, nor does it give you the convenient xor buffer to deal with
 * your crypted data for you. As such, it provides a slightly lower level of
 * abstraction apropos the backing store.
 *
 * Note that this function should only ever operate on a single nugget or its
 * behavior is undefined.
 */
typedef void (*sc_fn_crypt_data_custom)(
    const blfs_swappable_cipher_t * sc,
    uint64_t interblock_offset,
    uint64_t intrablock_offset,
    uint64_t num_blocks,
    uint64_t zero_str_length,
    uint64_t block_read_upper_bound,
    const uint8_t * nugget_key,
    const uint64_t kcs_keycount,
    const uint8_t * const kcs_keycount_ptr
);

/**
 * This struct defines the common read handle interface for algorithm swapping.
 * Cipher implementations can use either sc_fn_write_handle and
 * sc_fn_read_handle, sc_fn_crypt_data, or sc_fn_crypt_data_custom to control
 * StrongBox's crypt behavior at different levels of abstraction within
 * StrongBox.
 *
 * sc_fn_read_handle expects your cipher to accept a buffer and read into it
 * (from disk) a **decrypted** subset of nugget_data ciphertext. This is a good
 * choice if your cipher needs to work below the overread protection code (i.e.
 * Freestyle) and/or doesn't function like a stream cipher (i.e. AES-XTS). If
 * blfs_swappable_cipher_t::sc_fn_read_handle is defined,
 * blfs_swappable_cipher_t::sc_fn_write_handle must also be defined. Further,
 * the blfs_swappable_cipher_t::crypt_* properties **MUST** also be NULL.
 *
 * Note that this function should only ever operate on a single nugget or its
 * behavior is undefined. Also note that nugget_data[0] will always be aligned
 * with the start of the first affected flake.
 * 
 * ! This function should return the total number of bytes read in.
 */
typedef int (*sc_fn_read_handle)(
    uint8_t * buffer,
    const buselfs_state_t * buselfs_state,
    uint_fast32_t buffer_read_length,
    uint_fast32_t flake_index,
    uint_fast32_t flake_end,
    uint_fast32_t first_affected_flake,
    uint32_t flake_size,
    uint_fast32_t flakes_per_nugget,
    uint32_t mt_offset,
    const uint8_t * nugget_data,
    const uint8_t * nugget_key,
    uint_fast32_t nugget_offset,
    uint_fast32_t nugget_internal_offset,
    const blfs_keycount_t * count,
    int first_nugget,
    int last_nugget
);

/**
 * This struct defines the common write handle interface for algorithm swapping.
 * Cipher implementations can use either sc_fn_write_handle and
 * sc_fn_read_handle, sc_fn_crypt_data, or sc_fn_crypt_data_custom to control
 * StrongBox's crypt behavior at different levels of abstraction within
 * StrongBox.
 *
 * sc_fn_write_handle expects your cipher to accept some plaintext `buffer` and
 * write some **encrypted** subset of the current nugget to disk that includes
 * said buffer. This is a good choice if your cipher needs to work below the
 * overwrite protection code (i.e. Freestyle) and/or doesn't function like a
 * stream cipher (i.e. AES-XTS). If blfs_swappable_cipher_t::sc_fn_write_handle
 * is defined, blfs_swappable_cipher_t::sc_fn_read_handle must also be defined.
 * Further, the blfs_swappable_cipher_t::crypt_* properties **MUST** also be
 * NULL.
 *
 * Note that writes must be flake-atomic, by which I mean it is illegal for your
 * cipher to end up writing less than/some non-multiple of a flake's worth of
 * data to the backstore.
 * 
 * ! This function should return the total number of bytes written out.
 */
typedef int (*sc_fn_write_handle)(
    const uint8_t * buffer,
    const buselfs_state_t * buselfs_state,
    uint_fast32_t buffer_write_length,
    uint_fast32_t flake_index,
    uint_fast32_t flake_end,
    uint32_t flake_size,
    uint_fast32_t flakes_per_nugget,
    uint_fast32_t flake_internal_offset,
    uint32_t mt_offset,
    const uint8_t * nugget_key,
    uint_fast32_t nugget_offset,
    const blfs_keycount_t * count
);

/**
 * This struct defines a common handle for calculating the requested bytes per
 * flake of nugget metadata. It is not meant to be accessed directly.
 */
typedef uint32_t (*sc_fn_calc_handle)(
    const buselfs_state_t * buselfs_state
);

/**
 * A complete package representing a cipher in StrongBox
 */
struct blfs_swappable_cipher_t
{
    char * name;
    uint32_t enum_id;

    uint64_t output_size_bytes;
    uint64_t key_size_bytes;
    uint64_t nonce_size_bytes;

    uint32_t requested_md_bytes_per_nugget;

    sc_fn_crypt_data crypt_data;
    sc_fn_crypt_data_custom crypt_custom;
    sc_fn_read_handle read_handle;
    sc_fn_write_handle write_handle;

    sc_fn_calc_handle calc_handle;
};

/**
 * Accepts swappable_cipher_e enum value sc, which translates into a proper
 * cipher context used to populate set in blfs_swappable_cipher_t.
 *
 * @param sc
 */
void blfs_set_cipher_ctx(blfs_swappable_cipher_t * sc_ctx, swappable_cipher_e sc);

/**
 * Allows the cipher to calculate dynamically the bytes per nugget of metadata
 * StrongBox will allocate in the backing store during initialization. This
 * function should be called alongside blfs_set_cipher_ctx.
 */
void blfs_calculate_cipher_bytes_per_nugget(blfs_swappable_cipher_t * sc_ctx, buselfs_state_t * buselfs_state);

/**
 * Takes a string and converts it to its corresponding swappable_cipher_e enum
 * item as a string. Throws an exception if the passed string is invalid.
 *
 * @param  swappable_cipher_enum_item
 *
 * @return swappable_cipher_e
 */
swappable_cipher_e blfs_ident_string_to_cipher(const char * sc);

/**
 * Defines an abstraction layer allowing StrongBox to interface properly with
 * the swappable stream cipher crypt_data and crypt_data_custom handler.
 */
void blfs_swappable_crypt(blfs_swappable_cipher_t * sc,
                          uint8_t * crypted_data,
                          const uint8_t * data,
                          const uint32_t data_length,
                          const uint8_t * nugget_key,
                          const uint64_t kcs_keycount,
                          const uint64_t nugget_internal_offset);

#endif /* BLFS_SWAP_H_ */
