#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Internal
#include "staticnested.h"
#include "crapto1.h"


// Backdoored Nested Attack
//
// Attack conditions:
// * Backdoor, or a way to know the clear static nested nT
//
// Strategy:
// * Use backdoor on the targeted sector to get the clear static nested nT
// * Enumerate key candidates based on clear and encrypted nT
// * Use the resulting dictionary to bruteforce the key
//
//  Doegox, 2024, cf https://eprint.iacr.org/2024/1275 for more info

bool sen_check_key(
    uint32_t nt,
    uint32_t nt_enc,
    uint8_t par,
    uint8_t par_enc,
    uint32_t uid,
    uint64_t key)
{
    struct Crypto1State pcs;
    crypto1_init(&pcs, key);

    return crypto1_word(&pcs, nt ^ uid, 0) == (nt ^ nt_enc) &&
           filter(pcs.odd) == (par ^ par_enc);
}

bool sen_recover_keys(
    uint32_t nt,
    uint32_t nt_enc,
    uint8_t par,
    uint8_t par_enc,
    uint32_t uid,
    uint64_t **keys_p,
    size_t *keys_len_p)
{
    struct Crypto1State *states;
    uint64_t *keys;
    size_t keys_len = 0;

    states = lfsr_recovery32(nt ^ nt_enc, nt ^ uid);
    if (states == NULL)
        return false;

    for (size_t i = 0; states[i].odd || states[i].even; i++)
    {
        // only filtering possibility: last parity bit in keystream
        if (filter(states[i].odd) == (par ^ par_enc))
            states[keys_len++] = states[i];
    }

    keys = malloc(keys_len * sizeof(uint64_t));
    if (keys == NULL)
        return false;

    for (size_t i = 0; i < keys_len; i++)
    {
        lfsr_rollback_word(states + i, nt ^ uid, 0);
        crypto1_get_lfsr(states + i, keys + i);
    }

    crypto1_destroy(states);

    *keys_p = keys;
    *keys_len_p = keys_len;

    return true;
}


// Faster Backdoored Nested Attack against Fudan FM11RF08S tags
//
// Attack conditions:
// * Backdoor
// * keyA and keyB are different for the targeted sector
//
// Strategy:
// * Use backdoor on the targeted sector to get the clear static nested nT for keyA and for keyB
// * Generate 2 lists of key candidates based on clear and encrypted nT
// * Search couples of keyA/keyB satisfying some obscure relationship
// * Use the resulting dictionary to bruteforce the keyA (and staticnested_2x1nt_rf08s_1key for keyB)
//
//  Doegox, 2024, cf https://eprint.iacr.org/2024/1275 for more info

uint16_t lfsr16_rev8[0x10000];
uint16_t lfsr16_rev14[0x10000];

const uint8_t rot_a[16] = { 0, 8, 9, 4, 6, 11, 1, 15, 12, 5, 2, 13, 10, 14, 3, 7 };
const uint8_t rot_b[16] = { 0, 13, 1, 14, 4, 10, 15, 7, 5, 3, 8, 6, 9, 2, 12, 11 };

void init_lfsr16_table(void)
{
    uint16_t buffer[16] = { 0 }, x = 1;
    for (size_t i = 0; i < 65536 + 16; i++)
    {
        lfsr16_rev8[buffer[(i + 8) % 16]] = buffer[i % 16];
        lfsr16_rev14[buffer[(i + 14) % 16]] = buffer[i % 16];
        x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15;
        buffer[i % 16] = (x & 0xFF) << 8 | x >> 8;
    }
}

uint16_t compute_seednt16_nt32(
    uint32_t nt,
    uint64_t key)
{
    uint16_t seed = lfsr16_rev14[nt >> 16];

    for (size_t i = 0; i < 3; i++)
    {
        seed ^= rot_a[key & 0xF];
        key >>= 4;
        seed ^= rot_b[key & 0xF] << 4;
        key >>= 4;

        seed = lfsr16_rev8[seed];

        seed ^= rot_b[key & 0xF];
        key >>= 4;
        seed ^= rot_a[key & 0xF] << 4;
        key >>= 4;

        seed = lfsr16_rev8[seed];
    }

    return seed;
}