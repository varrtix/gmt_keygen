/* This file is part of project [fx-keygen].
 *
 * Copyright (c) 2024-Present VARRIX All Rights Reserved.
 *
 * Author: VARRTIX
 * Created Date: 2024/05/27
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

#include <fx/utils.h>

#ifdef __cplusplus
extern "C" {
#endif

#define fx_keychain_create(ctx, type, list)                                    \
  fx_keychain_create_ex(ctx, type, sizeof(list) / sizeof(*(list)), list)

#pragma mark - fx_ioctx_t
typedef struct fx_ioctx fx_ioctx_t;
typedef enum {
  FX_IOPT_INITCON = 0,
  FX_IOPT_OUTLET,
  FX_IOPT_PUBKEY,
  FX_IOPT_MAX,
} fx_ioctx_opt;

fx_ioctx_t *fx_ioctx_new(void);
void fx_ioctx_free(fx_ioctx_t *ctx);

int fx_ioctx_set(fx_ioctx_t *ctx, fx_ioctx_opt opt, void *val);

#pragma mark - fx_keychain_t
typedef struct fx_keychain fx_keychain_t;
typedef enum {
  FX_UNKNOWN_KEYCHAIN = 0,
  FX_AUC_KEYCHAIN,
  FX_ENC_KEYCHAIN,
  FX_BM_KEYCHAIN,
  FX_KMC_KEYCHAIN,
  FX_MAX_KEYCHAIN,
} fx_keychain_type;

fx_keychain_t *fx_keychain_create_ex(fx_ioctx_t *ctx, fx_keychain_type type,
                                     size_t n, const fx_bytes_t list[]);
fx_keychain_t *fx_keychain_create2(fx_ioctx_t *ctx, fx_keychain_type type,
                                   size_t n, ...);
void fx_keychain_destroy(fx_keychain_t *kc);

fx_keychain_type fx_keychain_get_type(fx_keychain_t *kc);
fx_bytes_t fx_keychain_get_kte(fx_keychain_t *kc);
fx_bytes_t fx_keychain_get_kek(fx_keychain_t *kc);
fx_bytes_t fx_keychain_get(fx_keychain_t *kc, size_t idx);

fx_bytes_t fx_keychain_encode(fx_keychain_t *kc);
fx_keychain_t *fx_keychain_decode(fx_bytes_t data);

int fx_ioctx_import(fx_ioctx_t *ctx, fx_keychain_type type, fx_bytes_t data);
fx_bytes_t fx_ioctx_export(fx_ioctx_t *ctx, fx_keychain_type type);

static inline int fx_ioctx_import_keychain(fx_ioctx_t *ctx, fx_keychain_t *kc) {
  fx_bytes_t data = fx_keychain_encode(kc);
  int ret = fx_ioctx_import(ctx, fx_keychain_get_type(kc), data);
  fx_bytes_free(&data);
  return ret;
}
static inline fx_keychain_t *fx_ioctx_export_keychain(fx_ioctx_t *ctx,
                                                      fx_keychain_type type) {
  fx_bytes_t data = fx_ioctx_export(ctx, type);
  fx_keychain_t *kc = fx_keychain_decode(data);
  fx_bytes_free(&data);
  return kc;
}

#ifdef __cplusplus
}
#endif