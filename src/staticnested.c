#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Internal
#include "staticnested.h"
#include "crapto1.h"

#define KEY_BLOCK_SIZE 0x200

void add_key(
    uint64_t key,
    uint64_t **keys,
    size_t *keys_len)
{
    if (*keys_len % KEY_BLOCK_SIZE == 0)
    {
        uint64_t *arr = realloc(*keys, (*keys_len + KEY_BLOCK_SIZE) * sizeof(uint64_t));
        if (arr == NULL)
        {
            fprintf(stderr, "Cannot allocate memory for keys\n");
            exit(EXIT_FAILURE);
        }
        *keys = arr;
    }
    (*keys)[(*keys_len)++] = key;
}

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

void generate_keys(
    uint32_t nt,
    uint64_t keystream,
    uint32_t uid,
    uint64_t **recovery_keys,
    size_t *recovery_keys_len)
{
    struct Crypto1State *revstate, *revstate_start, s;
    uint64_t lfsr;

    revstate = lfsr_recovery32(keystream >> 1, nt ^ uid);
    if (revstate == NULL)
    {
        fprintf(stderr, "Cannot allocate memory for revstate\n");
        exit(EXIT_FAILURE);
    }

    revstate_start = revstate;

    while ((revstate->odd != 0x0) || (revstate->even != 0x0))
    {
        s.odd = revstate->odd;
        s.even = revstate->even;

        // only filtering possibility: last parity bit in keystream
        if ((keystream & 1) == crypto1_bit(revstate, 0, 0))
        {
            lfsr_rollback_word(&s, nt ^ uid, 0);
            crypto1_get_lfsr(&s, &lfsr);

            add_key(lfsr, recovery_keys, recovery_keys_len);
        }

        revstate++;
    }

    crypto1_destroy(revstate_start);
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

static uint16_t i_lfsr16[1 << 16] = { 0 };
static uint16_t s_lfsr16[1 << 16] = { 0 };

static uint8_t rot_a[16] = { 0, 8, 9, 4, 6, 11, 1, 15, 12, 5, 2, 13, 10, 14, 3, 7 };
static uint8_t rot_b[16] = { 0, 13, 1, 14, 4, 10, 15, 7, 5, 3, 8, 6, 9, 2, 12, 11 };

#define MV_LFSR16(seed, dist) \
    s_lfsr16[(i_lfsr16[seed] + 65535 - dist) % 65535]

void init_lfsr16_table(void)
{
    for (uint16_t i = 0, x = 1; i < 65535; i++)
    {
        i_lfsr16[(x & 0xFF) << 8 | x >> 8] = i;
        s_lfsr16[i] = (x & 0xFF) << 8 | x >> 8;
        x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15;
    }
}

uint16_t compute_seednt16_nt32(
    uint32_t nt,
    uint64_t key)
{
    uint16_t seed = MV_LFSR16(nt >> 16, 14);

    for (size_t i = 0; i < 3; i++)
    {
        seed ^= rot_a[key & 0xF];
        key >>= 4;
        seed ^= rot_b[key & 0xF] << 4;
        key >>= 4;

        seed = MV_LFSR16(seed, 8);

        seed ^= rot_b[key & 0xF];
        key >>= 4;
        seed ^= rot_a[key & 0xF] << 4;
        key >>= 4;

        seed = MV_LFSR16(seed, 8);
    }

    return seed;
}