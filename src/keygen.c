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

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "fx/outlet.h"

#define FX_MAX_K_TE_LEN 16
#define FX_MAX_KEK_LEN 16

#pragma mark - protocol definition
typedef enum {
  FX_CMD_UNKNOWN = 0xCA00,
  FX_CMD_DEVAUTH_REQ = 0xCA01,
  FX_CMD_DEVAUTH = 0xCA02,
  FX_CMD_INITCON = 0xCA03,
  FX_CMD_CLRSS = 0xCA04,
  FX_CMD_MAX,
} fx_cmd_type;

typedef enum {
  FX_FTAG_UNKNOWN = 0xC000,
  FX_FTAG_PUBKEY = 0xC001,
  FX_FTAG_BMID = 0xC002,
  FX_FTAG_AUTHRND = 0xC003,
  FX_FTAG_AUTHDATA = 0xC004,
  FX_FTAG_ENC_INITCON = 0xC005,
  FX_FTAG_PROVID = 0xC006,
  FX_FTAG_KMCID = 0xC007,
  FX_FTAG_AUCID = 0xC008,
  FX_FTAG_KEK = 0xC009,
  FX_FTAG_KTE = 0xC00A,
  FX_FTAG_PUBKEYC = 0xC00B,
  FX_FTAG_MAX,
} fx_field_tag;

static inline int fx_field_tag_check(fx_field_tag tag) {
  return (tag > FX_FTAG_UNKNOWN) && (tag < FX_FTAG_MAX);
}

#pragma mark - fx_ioctx_t
typedef enum {
  FX_DEFAULT_IO = 0,
  FX_SK_IO,
  FX_TF_IO,
  FX_MAX_IO,
} fx_io_type;

static inline int fx_io_type_check(fx_io_type type) {
  return (type >= FX_DEFAULT_IO) && (type < FX_MAX_IO);
}

struct fx_ioctx {
  fx_field_t sig_pubkey;

  fx_outlet_t *outlet;
};

static int fx_ioctx_init(fx_ioctx_t *ctx, fx_bytes_t sig_pubkey) {
  ctx->sig_pubkey =
      fx_bytes_check(&sig_pubkey)
          ? fx_bytes2field_clone(FX_FTAG_PUBKEY, sig_pubkey)
          : fx_bytes2field(FX_FTAG_PUBKEY, fx_outlet_gen_ecckey(ctx->outlet));
  return fx_field_check(&ctx->sig_pubkey);
}

fx_ioctx_t *fx_ioctx_new(fx_outlet_t *outlet, fx_bytes_t sig_pubkey) {
  fx_ioctx_t *ctx = NULL;
  if (!outlet || !fx_io_type_check(type))
    goto end;

  ctx = (fx_ioctx_t *)calloc(1, sizeof(fx_ioctx_t));
  if (ctx) {
    ctx->type = type;
    ctx->outlet = outlet;
    if (fx_ioctx_init(ctx, sig_pubkey) != 1) {
      fx_ioctx_free(ctx);
      ctx = NULL;
    }
  }

end:
  return ctx;
}

void fx_ioctx_free(fx_ioctx_t *ctx) {
  if (ctx) {
    fx_field_free(&ctx->sig_pubkey);
    free(ctx);
  }
}

#define FX_BYTES_MAKE_TC_ARR(blist)                                            \
  fx_bytes_make_tc_arr(blist, sizeof(blist) / sizeof((*blist)))

static fx_bytes_t fx_bytes_make_tc_arr(const fx_bytes_t blist[], size_t n) {
  size_t mlen = 0;
  fx_bytes_t tc = fx_bytes_empty();

  if (n) {
    for (size_t i = 0; i < n; ++i)
      mlen += (blist + i)->len;

    if (mlen) {
      tc = fx_bytes_calloc(mlen);
      if (fx_bytes_check(&tc)) {
        mlen = 0;
        for (size_t i = 0; i < n; ++i) {
          memcpy(tc.ptr + mlen, (blist + i)->ptr, (blist + i)->len);
          mlen += (blist + i)->len;
        }
      }
    }
  }

  return tc;
}

static fx_bytes_t fx_bytes_make_tc(size_t n, ...) {
  va_list list;
  fx_bytes_t blist, tc = fx_bytes_empty();

  if (n) {
    blist = fx_bytes_calloc(sizeof(fx_bytes_t) * n);
    if (fx_bytes_check(&blist)) {
      va_start(list, n);
      for (size_t i = 0; i < n; ++i)
        *(((fx_bytes_t *)blist.ptr) + i) = va_arg(list, fx_bytes_t);
      va_end(list);

      tc = fx_bytes_make_tc_arr((fx_bytes_t *)blist.ptr, n);
      fx_bytes_free(&blist);
    }
  }

  return tc;
}

#pragma mark - fx_keychain_t
struct fx_keychain {};

// #pragma mark - fx_auc_t
// struct fx_auc {
//   fx_field_t tc_s;
//   fx_field_t sig_pubkey;
// };

// // concat content: Sign(dev_id || prov_id || kmc_id || k_te, sig_privkey)
// fx_auc_t *fx_auc_keygen(fx_ioctx_t *ctx, fx_bytes_t dev_id, fx_bytes_t
// prov_id,
//                         fx_bytes_t kmc_id) {
//   fx_auc_t *auc = NULL;
//   fx_bytes_t tc = fx_bytes_empty(), blist[] = {dev_id, prov_id, kmc_id};
//   if (!ctx || !fx_bytes_check(&dev_id) || !fx_bytes_check(&prov_id) ||
//       !fx_bytes_check(&kmc_id))
//     goto end;

//   tc = FX_BYTES_MAKE_TC_ARR(blist);
//   auc = (fx_auc_t *)calloc(1, sizeof(fx_auc_t));
//   if (!auc)
//     goto cleanup;

//   auc->tc_s = fx_bytes2field(FX_FTAG_EX_SIGNED_TC,
//                              fx_outlet_ecc_sign(ctx->outlet, tc, 1));
//   if (fx_field_check(&auc->tc_s)) {
//     auc->k_te = fx_bytes2field(
//         FX_FTAG_KTE, fx_outlet_gen_random(ctx->outlet, FX_MAX_K_TE_LEN));
//     if (fx_field_check(&auc->k_te)) {
//       auc->sig_pubkey = fx_field_clone(ctx->sig_pubkey);
//       if (fx_field_check(&auc->sig_pubkey))
//         goto end;
//     }
//   }

// cleanup:
//   fx_bytes_free(&tc);
//   if (auc) {
//     fx_auc_free(auc);
//     auc = NULL;
//   }

// end:
//   return auc;
// }

// void fx_auc_free(fx_auc_t *auc) {
//   if (auc) {
//     fx_field_free(&auc->tc_s);
//     fx_field_free(&auc->k_te);
//     fx_field_free(&auc->sig_pubkey);
//     free(auc);
//   }
// }

// #pragma mark - edpt_enc_t
// struct fx_enc {
//   fx_bytes_t sig_dev_id;
//   fx_bytes_t sig_prov_id;
//   fx_bytes_t sig_kmc_id;
//   fx_bytes_t sig_auc_id;
//   fx_bytes_t sig_pubkey;
// };

// fx_enc_t *fx_enc_new(void) { return (fx_enc_t *)malloc(sizeof(fx_enc_t)); }

// void fx_enc_free(fx_enc_t *enc) {
//   if (enc) {
//     fx_bytes_free(&enc->sig_dev_id);
//     fx_bytes_free(&enc->sig_prov_id);
//     fx_bytes_free(&enc->sig_kmc_id);
//     fx_bytes_free(&enc->sig_auc_id);
//     fx_bytes_free(&enc->sig_pubkey);
//     free(enc);
//   }
// }

// int fx_enc_keygen(fx_bytes_t dev_id, fx_bytes_t prov_id, fx_bytes_t kmc_id,
//                   fx_bytes_t auc_id, fx_enc_t *enc) {
//   return 0;
// }

// #pragma mark - fx_bm_t
// struct fx_bm {
//   fx_bytes_t trusted_chain;
// };

// fx_bm_t *fx_bm_new(void) { return (fx_bm_t *)malloc(sizeof(fx_bm_t)); }

// void fx_bm_free(fx_bm_t *bm) {
//   if (bm) {
//     fx_bytes_free(&bm->trusted_chain);
//     free(bm);
//   }
// }

// int fx_bm_keygen(fx_bytes_t dev_id, fx_bytes_t prov_id, fx_bytes_t kmc_id,
//                  fx_bm_t *bm) {
//   return 0;
// }

// #pragma mark - fx_kmc_t
// struct fx_kmc {
//   fx_bytes_t sig_pubkey;
//   fx_bytes_t kek;
// };

// fx_kmc_t *fx_kmc_new(void) { return (fx_kmc_t *)malloc(sizeof(fx_kmc_t)); }

// void fx_kmc_free(fx_kmc_t *kmc) {
//   if (kmc) {
//     fx_bytes_free(&kmc->sig_pubkey);
//     fx_bytes_free(&kmc->kek);
//     free(kmc);
//   }
// }

// int fx_kmc_keygen(fx_bytes_t dev_id, fx_bytes_t prov_id, fx_bytes_t auc_id,
//                   fx_kmc_t *kmc) {
//   return 0;
// }
