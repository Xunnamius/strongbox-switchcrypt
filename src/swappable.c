/**
 * <description>
 *
 * @author Bernard Dickens
 */

#include "swappable.h"

void blfs_get_stream_cipher(blfs_stream_cipher_t * stream_cipher_struct, stream_cipher_e stream_cipher)
{
    // TODO: fix me!
    // sc_context_collection_t collection;
    // blfs_to_stream_context_collection(&collection, stream_cipher);

    // buselfs_state->default_crypt_context = collection.crypt_fn;
    // buselfs_state->read_context_overwrite = collection.read_fn;
    // buselfs_state->write_context_overwrite = collection.write_fn;
    // buselfs_state->current_sc_attributes = collection.crypt_attr;
    
    // IFDEBUG(dzlog_info(":cipher stream context loaded successfully:"));
    // IFDEBUG(dzlog_info("%s", active_sc_attributes->name));
    // IFDEBUG(dzlog_info("description: %s", active_sc_attributes->description));

    // TODO: fix me!
    // switch(stream_cipher)
    // {
    //     case sc_default:
    //     case sc_chacha20:
    //     {
    //         collection->crypt_fn = &sc_impl_chacha20;
    //         collection->crypt_attr = &sc_attributes_chacha20;
    //         collection->read_fn = NULL;
    //         collection->write_fn = NULL;
    //         break;
    //     }

    //     case sc_aes128_ctr:
    //     {
    //         collection->crypt_fn = &sc_impl_aes128_ctr;
    //         collection->crypt_attr = &sc_attributes_aes128_ctr;
    //         collection->read_fn = NULL;
    //         collection->write_fn = NULL;
    //         break;
    //     }

    //     case sc_aes256_ctr:
    //     {
    //         collection->crypt_fn = &sc_impl_aes256_ctr;
    //         collection->crypt_attr = &sc_attributes_aes256_ctr;
    //         collection->read_fn = NULL;
    //         collection->write_fn = NULL;
    //         break;
    //     }

    //     case sc_aes512_ctr:
    //     {
    //         collection->crypt_fn = &sc_impl_aes512_ctr;
    //         collection->crypt_attr = &sc_attributes_aes512_ctr;
    //         collection->read_fn = NULL;
    //         collection->write_fn = NULL;
    //         break;
    //     }

    //     case sc_salsa8:
    //     {
    //         collection->crypt_fn = &sc_impl_salsa8;
    //         collection->crypt_attr = &sc_attributes_salsa8;
    //         collection->read_fn = NULL;
    //         collection->write_fn = NULL;
    //         break;
    //     }

    //     case sc_salsa12:
    //     {
    //         collection->crypt_fn = &sc_impl_salsa12;
    //         collection->crypt_attr = &sc_attributes_salsa12;
    //         collection->read_fn = NULL;
    //         collection->write_fn = NULL;
    //         break;
    //     }

    //     case sc_salsa20:
    //     {
    //         collection->crypt_fn = &sc_impl_salsa20;
    //         collection->crypt_attr = &sc_attributes_salsa20;
    //         collection->read_fn = NULL;
    //         collection->write_fn = NULL;
    //         break;
    //     }

    //     case sc_hc128:
    //     {
    //         collection->crypt_fn = &sc_impl_hc128;
    //         collection->crypt_attr = &sc_attributes_hc128;
    //         collection->read_fn = NULL;
    //         collection->write_fn = NULL;
    //         break;
    //     }

    //     case sc_rabbit:
    //     {
    //         collection->crypt_fn = &sc_impl_rabbit;
    //         collection->crypt_attr = &sc_attributes_rabbit;
    //         collection->read_fn = NULL;
    //         collection->write_fn = NULL;
    //         break;
    //     }

    //     case sc_sosemanuk:
    //     {
    //         collection->crypt_fn = &sc_impl_sosemanuk;
    //         collection->crypt_attr = &sc_attributes_sosemanuk;
    //         collection->read_fn = NULL;
    //         collection->write_fn = NULL;
    //         break;
    //     }

    //     case sc_chacha8_neon:
    //     {
    //         collection->crypt_fn = &sc_impl_chacha8_neon;
    //         collection->crypt_attr = &sc_attributes_chacha8_neon;
    //         collection->read_fn = NULL;
    //         collection->write_fn = NULL;
    //         break;
    //     }

    //     case sc_chacha12_neon:
    //     {
    //         collection->crypt_fn = &sc_impl_chacha12_neon;
    //         collection->crypt_attr = &sc_attributes_chacha12_neon;
    //         collection->read_fn = NULL;
    //         collection->write_fn = NULL;
    //         break;
    //     }

    //     case sc_chacha20_neon:
    //     {
    //         collection->crypt_fn = &sc_impl_chacha20_neon;
    //         collection->crypt_attr = &sc_attributes_chacha20_neon;
    //         collection->read_fn = NULL;
    //         collection->write_fn = NULL;
    //         break;
    //     }

    //     case sc_freestyle_fast:
    //     {
    //         collection->crypt_fn = &sc_impl_freestyle_fast;
    //         collection->crypt_attr = &sc_attributes_freestyle_fast;
    //         collection->read_fn = NULL;
    //         collection->write_fn = NULL;
    //         break;
    //     }

    //     case sc_freestyle_balanced:
    //     {
    //         collection->crypt_fn = &sc_impl_freestyle_balanced;
    //         collection->crypt_attr = &sc_attributes_freestyle_balanced;
    //         collection->read_fn = NULL;
    //         collection->write_fn = NULL;
    //         break;
    //     }

    //     case sc_freestyle_secure:
    //     {
    //         collection->crypt_fn = &sc_impl_freestyle_secure;
    //         collection->crypt_attr = &sc_attributes_freestyle_secure;
    //         collection->read_fn = NULL;
    //         collection->write_fn = NULL;
    //         break;
    //     }

    //     case sc_not_impl:
    //     {
    //         Throw(EXCEPTION_SC_ALGO_NO_IMPL);
    //         break;
    //     }

    //     default:
    //     {
    //         Throw(EXCEPTION_SC_ALGO_NOT_FOUND);
    //         break;
    //     }
    // }
}

stream_cipher_e stream_string_to_cipher(const char * stream_cipher_str)
{
    // TODO: fix me!
    // stream_cipher_e cipher = sc_not_impl;

    // if(strcmp(stream_cipher_str, "sc_default") == 0)
    //     cipher = sc_default;

    // else if(strcmp(stream_cipher_str, "sc_aes128_ctr") == 0)
    //     cipher = sc_aes128_ctr;
    
    // else if(strcmp(stream_cipher_str, "sc_aes256_ctr") == 0)
    //     cipher = sc_aes256_ctr;

    // else if(strcmp(stream_cipher_str, "sc_salsa8") == 0)
    //     cipher = sc_salsa8;
    
    // else if(strcmp(stream_cipher_str, "sc_salsa12") == 0)
    //     cipher = sc_salsa12;

    // else if(strcmp(stream_cipher_str, "sc_salsa20") == 0)
    //     cipher = sc_salsa20;

    // else if(strcmp(stream_cipher_str, "sc_hc128") == 0)
    //     cipher = sc_hc128;

    // else if(strcmp(stream_cipher_str, "sc_rabbit") == 0)
    //     cipher = sc_rabbit;
    
    // else if(strcmp(stream_cipher_str, "sc_sosemanuk") == 0)
    //     cipher = sc_sosemanuk;
    
    // else if(strcmp(stream_cipher_str, "sc_chacha20") == 0)
    //     cipher = sc_chacha20;

    // else if(strcmp(stream_cipher_str, "sc_chacha8_neon") == 0)
    //     cipher = sc_chacha8_neon;

    // else if(strcmp(stream_cipher_str, "sc_chacha12_neon") == 0)
    //     cipher = sc_chacha12_neon;
    
    // else if(strcmp(stream_cipher_str, "sc_chacha20_neon") == 0)
    //     cipher = sc_chacha20_neon;
    
    // else if(strcmp(stream_cipher_str, "sc_freestyle_fast") == 0)
    //     cipher = sc_freestyle_fast;
    
    // else if(strcmp(stream_cipher_str, "sc_freestyle_balanced") == 0)
    //     cipher = sc_freestyle_balanced;
    
    // else if(strcmp(stream_cipher_str, "sc_freestyle_secure") == 0)
    //     cipher = sc_freestyle_secure;

    // else
    //     Throw(EXCEPTION_STRING_TO_CIPHER_FAILED);

    // return cipher;
}
