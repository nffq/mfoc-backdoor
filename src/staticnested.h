#ifndef STATIC_NESTED__
#define STATIC_NESTED__

#include <nfc/nfc-types.h>

void add_key(uint64_t key, uint64_t **keys, size_t *keys_len);
void generate_keys(uint32_t nt, uint8_t par, uint32_t nt_enc, uint8_t par_enc, uint32_t uid, uint64_t **keys, size_t *keys_len);

void init_lfsr16_table(void);
uint16_t compute_seednt16_nt32(uint32_t nt, uint64_t key);

#endif