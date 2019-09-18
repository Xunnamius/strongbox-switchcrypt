#include "cipher/freestyle_secure.h"

static int read_handle(uint8_t * buffer,
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
                    int last_nugget)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    return sc_generic_freestyle_read_handle(
        FREESTYLE_SECURE,
        buffer,
        buselfs_state,
        buffer_read_length,
        flake_index,
        flake_end,
        first_affected_flake,
        flake_size,
        flakes_per_nugget,
        mt_offset,
        nugget_data,
        nugget_key,
        nugget_offset,
        nugget_internal_offset,
        count,
        first_nugget,
        last_nugget
    );

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

static int write_handle(const uint8_t * buffer,
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
                        const blfs_keycount_t * count)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    return sc_generic_freestyle_write_handle(
        FREESTYLE_SECURE,
        buffer,
        buselfs_state,
        buffer_write_length,
        flake_index,
        flake_end,
        flake_size,
        flakes_per_nugget,
        flake_internal_offset,
        mt_offset,
        nugget_key,
        nugget_offset,
        count
    );

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void sc_impl_freestyle_secure(blfs_swappable_cipher_t * sc)
{
    sc_impl_freestyle(sc);
    sc->read_handle = &read_handle;
    sc->write_handle = &write_handle;

    sc->name = "Freestyle @ SECURE configuration";
    sc->enum_id = sc_freestyle_secure;
}
