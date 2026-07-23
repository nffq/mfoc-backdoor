#ifndef MFOC_H__
#define MFOC_H__

#include <nfc/nfc-types.h>

enum mf_commands
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

struct mf_key
{
    bool found;
    uint64_t key;
    uint32_t nt;
    uint32_t nt_enc;
    uint8_t par;
    uint8_t par_enc;
};

extern nfc_device *pdi;
extern nfc_target *pnt;

void mf_init(void);
void mf_destroy(void);
void mf_configure(void);

void mf_select_target(void);
void mf_device_set(nfc_property property, bool enable);

bool mf_read(uint8_t blk, uint8_t *blk_p);
bool mf_auth(uint8_t cmd, uint8_t blk, uint64_t key, uint32_t uid);
bool mf_nested_auth(uint8_t cmd, uint8_t cmd_enc, uint8_t blk, uint64_t key, uint32_t uid, uint32_t *nt_p, uint8_t *par_p, bool decrypt);

#endif