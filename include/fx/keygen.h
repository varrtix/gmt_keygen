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

#include <fx/outlet.h>
#include <fx/utils.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma mark - fx_ioctx_t
typedef enum {
  FX_DEFAULT_IO = 0,
  FX_SK_IO,
  FX_TF_IO,
  FX_MAX_IO,
} fx_io_type;

typedef struct fx_ioctx fx_ioctx_t;

fx_ioctx_t *fx_ioctx_new(fx_io_type type, fx_bytes_t sig_pubkey,
                         fx_outlet_t *outlet);
void fx_ioctx_free(fx_ioctx_t *ctx);

#pragma mark - fx_auc_t
typedef struct fx_auc fx_auc_t;

fx_auc_t *fx_auc_keygen(fx_ioctx_t *ctx, fx_bytes_t dev_id, fx_bytes_t prov_id,
                        fx_bytes_t kmc_id);
void fx_auc_free(fx_auc_t *auc);

#pragma mark - fx_enc_t
typedef struct fx_enc fx_enc_t;

fx_enc_t *fx_enc_new(void);
void fx_enc_free(fx_enc_t *enc);

int fx_enc_keygen(fx_bytes_t dev_id, fx_bytes_t prov_id, fx_bytes_t kmc_id,
                  fx_bytes_t auc_id, fx_enc_t *enc);

#pragma mark - fx_bm_t
typedef struct fx_bm fx_bm_t;

fx_bm_t *fx_bm_new(void);
void fx_bm_free(fx_bm_t *bm);

int fx_bm_keygen(fx_bytes_t dev_id, fx_bytes_t prov_id, fx_bytes_t kmc_id,
                 fx_bm_t *bm);

#pragma mark - fx_kmc_t
typedef struct fx_kmc fx_kmc_t;

fx_kmc_t *fx_kmc_new(void);
void fx_kmc_free(fx_kmc_t *kmc);

int fx_kmc_keygen(fx_bytes_t dev_id, fx_bytes_t prov_id, fx_bytes_t auc_id,
                  fx_kmc_t *kmc);

#ifdef __cplusplus
}
#endif