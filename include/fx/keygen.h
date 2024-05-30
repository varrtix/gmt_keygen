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

#pragma mark - epdt_auc_t
typedef struct epdt_auc epdt_auc_t;

epdt_auc_t *epdt_auc_new(void);
void epdt_auc_free(epdt_auc_t *auc);

int epdt_auc_keygen(fx_bytes_t dev_id, fx_bytes_t prov_id, fx_bytes_t kmc_id,
                    epdt_auc_t *auc);

#pragma mark - epdt_enc_t
typedef struct epdt_enc epdt_enc_t;

epdt_enc_t *epdt_enc_new(void);
void epdt_enc_free(epdt_enc_t *enc);

int epdt_enc_keygen(fx_bytes_t dev_id, fx_bytes_t prov_id, fx_bytes_t kmc_id,
                    fx_bytes_t auc_id, epdt_enc_t *enc);

#pragma mark - epdt_bm_t
typedef struct epdt_bm epdt_bm_t;

epdt_bm_t *epdt_bm_new(void);
void epdt_bm_free(epdt_bm_t *bm);

int epdt_bm_keygen(fx_bytes_t dev_id, fx_bytes_t prov_id, fx_bytes_t kmc_id,
                   epdt_bm_t *bm);

#pragma mark - epdt_kmc_t
typedef struct epdt_kmc epdt_kmc_t;

epdt_kmc_t *epdt_kmc_new(void);
void epdt_kmc_free(epdt_kmc_t *kmc);

int epdt_kmc_keygen(fx_bytes_t dev_id, fx_bytes_t prov_id, fx_bytes_t auc_id,
                    epdt_kmc_t *kmc);

#ifdef __cplusplus
}
#endif