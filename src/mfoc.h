#ifndef MFOC_H__
#define MFOC_H__

#include <nfc/nfc-types.h>

// Number of trailers == number of sectors
// Mifare Classic Mini
#define NR_TRAILERS_MINI  5
// Mifare Classic 1k 16x64b = 16
#define NR_TRAILERS_1k   16
// Mifare Classic 2k 32x64b
#define NR_TRAILERS_2k   32
// Mifare Classic 4k 32x64b + 8*256b = 40
#define NR_TRAILERS_4k   40

#define MAX_FRAME_LEN 264


enum mf_cmd
{
    MC_AUTH_A = 0x60,
    MC_AUTH_B = 0x61,
    MC_READ = 0x30,
    MC_WRITE = 0xA0,
    MC_TRANSFER = 0xB0,
    MC_DECREMENT = 0xC0,
    MC_INCREMENT = 0xC1,
    MC_STORE = 0xC2
};

struct mf_sector
{
    bool found_key_a;
    bool found_key_b;
    uint64_t key_a;
    uint64_t key_b;
    uint32_t nt_a;
    uint32_t nt_b;
    uint32_t nt_enc_a;
    uint32_t nt_enc_b;
    uint8_t par_a;
    uint8_t par_b;
    uint8_t par_enc_a;
    uint8_t par_enc_b;
};

extern const nfc_modulation nm;
extern nfc_context *ctx;
extern nfc_device *pdi;
extern nfc_target *pnt;

void num_to_bytes(uint8_t *dest, uint64_t n, uint32_t len);
uint64_t bytes_to_num(uint8_t *src, uint32_t len);
uint8_t sector_to_trailer(uint8_t sector);

void mf_init(void);
void mf_destroy(void);
void mf_configure(void);

void mf_select_target(void);
void mf_device_set(nfc_property property, bool enable);

bool mf_rats_is_2k(void);
bool mf_read(uint8_t blk, uint8_t *blk_p);
bool mf_auth(uint8_t cmd, uint8_t blk, uint64_t key, uint32_t uid);
bool mf_nested_auth(uint8_t cmd, uint8_t cmd_enc, uint8_t blk, uint64_t key, uint32_t uid, uint32_t *nt_p, uint8_t *par_p, bool decrypt);

#endif