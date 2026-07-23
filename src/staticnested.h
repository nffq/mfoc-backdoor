#ifndef STATICNESTED_H__
#define STATICNESTED_H__

#include <nfc/nfc-types.h>


bool sen_check_key(uint32_t nt, uint32_t nt_enc, uint8_t par, uint8_t par_enc, uint32_t uid, uint64_t key);
bool sen_recover_keys(uint32_t nt, uint32_t nt_enc, uint8_t par, uint8_t par_enc, uint32_t uid, uint64_t **keys_p, size_t *keys_len_p);

void init_lfsr16_table(void);
uint16_t compute_seednt16_nt32(uint32_t nt, uint64_t key);

#endif