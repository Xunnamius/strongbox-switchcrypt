#ifndef BLFS_CIPHERS_H_
#define BLFS_CIPHERS_H_

// ! If you're adding a new cipher, don't forget to add its source to ciphers/
// ! and a new line to represent the cipher in this file (below)

#include "cipher/chacha20.h"
#include "cipher/chacha20_neon.h"
#include "cipher/chacha12_neon.h"
#include "cipher/chacha8_neon.h"
#include "cipher/salsa20.h"
#include "cipher/salsa12.h"
#include "cipher/salsa8.h"
#include "cipher/freestyle_secure.h"
#include "cipher/freestyle_balanced.h"
#include "cipher/freestyle_fast.h"
#include "cipher/aes128_ctr.h"
#include "cipher/aes256_ctr.h"
#include "cipher/hc128.h"
#include "cipher/rabbit.h"
#include "cipher/sosemanuk.h"

#endif /* BLFS_CIPHERS_H_ */
