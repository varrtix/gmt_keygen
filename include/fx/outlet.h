/* This file is part of project [fx-keygen].
 *
 * Copyright (c) 2024-Present VARRIX All Rights Reserved.
 *
 * Author: VARRTIX
 * Created Date: 2022/08/01
 * Modified Date: 2024/05/27
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include <fx/utils.h>

typedef void fx_obj_t;
typedef struct fx_outlet fx_outlet_t;
typedef struct fx_port fx_port_t;
typedef struct fx_port_list fx_port_list_t;

#pragma mark - fx_port_t
typedef enum {
  FX_DEFAULT_PORT = 0,
  FX_DEV_PORT,
  FX_APP_PORT,
  FX_CONTA_PORT,
  FX_MAX_PORT,
} fx_port_type;

typedef enum {
  FX_PF_CREAT = 0x01,
  FX_PF_OPEN = 0x02,
  FX_PF_VALID_FLAGS = (FX_PF_CREAT | FX_PF_OPEN),
} fx_port_flag_t;

fx_port_t *fx_port_new(fx_port_type type, fx_bytes_t name, int flags,
                       fx_outlet_t *outlet, fx_obj_t *obj);
void fx_port_free(fx_port_t *port);

int fx_port_open(fx_port_t *port);
int fx_port_close(fx_port_t *port);
int fx_port_busy(fx_port_t *port);
fx_obj_t **fx_port_export(fx_port_t *port);

#pragma mark - fx_port_list_t
fx_port_list_t *fx_port_list_new(fx_port_type type, fx_obj_t *obj);
void fx_port_list_free(fx_port_list_t *plist);

size_t fx_port_list_size(fx_port_list_t *plist);
const char *fx_port_list_peek_name2char(fx_port_list_t *plist, size_t idx,
                                        size_t *nlen);
fx_bytes_t fx_port_list_get_name(fx_port_list_t *plist, size_t idx);
int fx_port_list_export2char(fx_port_list_t *plist, char **list, size_t *nlen);

#pragma mark - fx_outlet_t
fx_outlet_t *fx_outlet_new(const char *authkey, const char *pin);
void fx_outlet_free(fx_outlet_t *outlet);

const char *fx_outlet_peek_pin2char(fx_outlet_t *outlet);
fx_bytes_t fx_outlet_get_pin(fx_outlet_t *outlet);
fx_obj_t **fx_outlet_export(fx_outlet_t *outlet, fx_port_type type);
int fx_outlet_set_port(fx_outlet_t *outlet, fx_port_type type, fx_port_t *port);
int fx_outlet_validate_port(fx_outlet_t *outlet, fx_port_type type);

#pragma mark - crypto
typedef enum {
  FX_FC_SMS4_ECB = 0,
  FX_FC_SMS4_CBC,
  FX_FC_SMS4_CFB,
  FX_FC_SMS4_OFB,
  FX_FC_MAX,
} fx_cipher_type;

static inline int fx_cipher_type_check(fx_cipher_type type) {
  return (type >= FX_FC_SMS4_ECB) && (type < FX_FC_MAX);
}

fx_bytes_t fx_outlet_gen_ecckey(fx_outlet_t *outlet);
fx_bytes_t fx_outlet_gen_random(fx_outlet_t *outlet, size_t len);
fx_bytes_t fx_outlet_ecc_sign(fx_outlet_t *outlet, fx_bytes_t in, int preproc);
fx_bytes_t fx_outlet_sm3_digest(fx_outlet_t *outlet, fx_bytes_t in);
fx_bytes_t fx_outlet_encrypt(fx_outlet_t *outlet, fx_cipher_type type,
                             fx_bytes_t key, fx_bytes_t iv, fx_bytes_t in);
fx_bytes_t fx_outlet_decrypt(fx_outlet_t *outlet, fx_cipher_type type,
                             fx_bytes_t key, fx_bytes_t iv, fx_bytes_t in);
fx_bytes_t fx_outlet_ecc_encrypt(fx_outlet_t *outlet, fx_bytes_t pubkey,
                                 fx_bytes_t in);

#ifdef __cplusplus
}
#endif