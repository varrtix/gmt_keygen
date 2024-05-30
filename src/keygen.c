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

#include "fx/keygen.h"

#include <stdlib.h>

#include "fx/outlet.h"

// #define EPDT_MAX_K_TE_LEN 16

#pragma mark - edpt_auc_t
struct epdt_auc {
  fx_bytes_t trusted_chain;
  fx_bytes_t auc_key;
  fx_bytes_t sig_pubkey;
};

epdt_auc_t *epdt_auc_new(void) {
  return (epdt_auc_t *)malloc(sizeof(epdt_auc_t));
}

void epdt_auc_free(epdt_auc_t *auc) {
  if (auc) {
    fx_bytes_free(&auc->trusted_chain);
    fx_bytes_free(&auc->auc_key);
    fx_bytes_free(&auc->sig_pubkey);
    free(auc);
  }
}

int epdt_auc_keygen(fx_bytes_t dev_id, fx_bytes_t prov_id, fx_bytes_t kmc_id,
                    epdt_auc_t *auc) {
  // fx_port_list_t *layers = fx_port_list_new(1);

  return 0;
}

#pragma mark - edpt_enc_t
struct epdt_enc {
  fx_bytes_t sig_dev_id;
  fx_bytes_t sig_prov_id;
  fx_bytes_t sig_kmc_id;
  fx_bytes_t sig_auc_id;
  fx_bytes_t sig_pubkey;
};

epdt_enc_t *epdt_enc_new(void) {
  return (epdt_enc_t *)malloc(sizeof(epdt_enc_t));
}

void epdt_enc_free(epdt_enc_t *enc) {
  if (enc) {
    fx_bytes_free(&enc->sig_dev_id);
    fx_bytes_free(&enc->sig_prov_id);
    fx_bytes_free(&enc->sig_kmc_id);
    fx_bytes_free(&enc->sig_auc_id);
    fx_bytes_free(&enc->sig_pubkey);
    free(enc);
  }
}

int epdt_enc_keygen(fx_bytes_t dev_id, fx_bytes_t prov_id, fx_bytes_t kmc_id,
                    fx_bytes_t auc_id, epdt_enc_t *enc) {
  return 0;
}

#pragma mark - epdt_bm_t
struct epdt_bm {
  fx_bytes_t trusted_chain;
};

epdt_bm_t *epdt_bm_new(void) { return (epdt_bm_t *)malloc(sizeof(epdt_bm_t)); }

void epdt_bm_free(epdt_bm_t *bm) {
  if (bm) {
    fx_bytes_free(&bm->trusted_chain);
    free(bm);
  }
}

int epdt_bm_keygen(fx_bytes_t dev_id, fx_bytes_t prov_id, fx_bytes_t kmc_id,
                   epdt_bm_t *bm) {
  return 0;
}

#pragma mark - epdt_kmc_t
struct epdt_kmc {
  fx_bytes_t sig_pubkey;
  fx_bytes_t k_te;
};

epdt_kmc_t *epdt_kmc_new(void) {
  return (epdt_kmc_t *)malloc(sizeof(epdt_kmc_t));
}

void epdt_kmc_free(epdt_kmc_t *kmc) {
  if (kmc) {
    fx_bytes_free(&kmc->sig_pubkey);
    fx_bytes_free(&kmc->k_te);
    free(kmc);
  }
}

int epdt_kmc_keygen(fx_bytes_t dev_id, fx_bytes_t prov_id, fx_bytes_t auc_id,
                    epdt_kmc_t *kmc) {
  return 0;
}
