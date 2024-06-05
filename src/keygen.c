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

#include "base64.h"
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
  FX_FTAG_EX_ENCID = 0xD000,
  FX_FTAG_EX_TC = 0xD001,
  FX_FTAG_EX_STC = 0xD002,
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

static inline int fx_ioctx_opt_check(fx_ioctx_opt opt) {
  return (opt >= FX_IOPT_INITCON) && (opt < FX_IOPT_MAX);
}

struct fx_ioctx {
  fx_outlet_t *outlet;
  fx_field_t pubkey;
};

static int fx_ioctx_set_initcon(fx_ioctx_t *ctx, void *val) { return 0; }

static int fx_ioctx_set_outlet(fx_ioctx_t *ctx, fx_outlet_t *outlet) {
  int ret = 1;
  if (ctx->outlet = outlet) {
    if (!fx_field_check(&ctx->pubkey)) {
      ctx->pubkey =
          fx_bytes2field(FX_FTAG_PUBKEY, fx_outlet_gen_ecckey(outlet));
      if (!fx_field_check(&ctx->pubkey)) {
        ctx->outlet = NULL;
        ret = 0;
      }
    }
  } else if (fx_field_check(&ctx->pubkey)) {
    fx_field_free(&ctx->pubkey);
  }
  return ret;
}

static int fx_ioctx_set_pubkey(fx_ioctx_t *ctx, fx_bytes_t *pubkey) {
  fx_field_free(&ctx->pubkey);
  if (pubkey)
    ctx->pubkey = fx_bytes2field_clone(FX_FTAG_PUBKEY, *pubkey);
  return 1;
}

fx_ioctx_t *fx_ioctx_new(void) {
  return (fx_ioctx_t *)calloc(1, sizeof(fx_ioctx_t));
}

void fx_ioctx_free(fx_ioctx_t *ctx) {
  if (ctx) {
    fx_field_free(&ctx->pubkey);
    free(ctx);
  }
}

int fx_ioctx_set(fx_ioctx_t *ctx, fx_ioctx_opt opt, void *val) {
  if (ctx)
    switch (opt) {
    case FX_IOPT_INITCON:
      return fx_ioctx_set_initcon(ctx, val);
    case FX_IOPT_OUTLET:
      return fx_ioctx_set_outlet(ctx, (fx_outlet_t *)val);
    case FX_IOPT_PUBKEY:
      return fx_ioctx_set_pubkey(ctx, (fx_bytes_t *)val);
    default:
      break;
    }
  return 0;
}

#pragma mark - fx_keychain_t
struct fx_keychain {
  fx_keychain_type type;
  fx_field_t pubkey, stc;
  fx_chunk_t *tc;
};

static inline uint16_t fx_keychain_type2tag(fx_keychain_type type) {
  switch (type) {
  case FX_AUC_KEYCHAIN:
    return FX_FTAG_AUCID;
  case FX_ENC_KEYCHAIN:
    return FX_FTAG_EX_ENCID;
  case FX_BM_KEYCHAIN:
    return FX_FTAG_BMID;
  case FX_KMC_KEYCHAIN:
    return FX_FTAG_KMCID;
  default:
    return FX_FTAG_UNKNOWN;
  }
}

static inline fx_keychain_type fx_keychain_tag2type(uint16_t tag) {
  switch (tag) {
  case FX_FTAG_AUCID:
    return FX_AUC_KEYCHAIN;
  case FX_FTAG_EX_ENCID:
    return FX_ENC_KEYCHAIN;
  case FX_FTAG_BMID:
    return FX_BM_KEYCHAIN;
  case FX_FTAG_KMCID:
    return FX_KMC_KEYCHAIN;
  default:
    return FX_UNKNOWN_KEYCHAIN;
  }
}

static inline int fx_keychain_type_check(fx_keychain_type type) {
  return (type > FX_UNKNOWN_KEYCHAIN) && (type < FX_MAX_KEYCHAIN);
}

static inline fx_field_t fx_keychain_stc_make(fx_outlet_t *outlet,
                                              fx_chunk_t *tc) {
  fx_bytes_t tcb = fx_chunk_flat(tc);
  fx_field_t tcf =
      fx_bytes2field(FX_FTAG_EX_STC, fx_outlet_ecc_sign(outlet, tcb, 1));
  fx_bytes_free(&tcb);
  return tcf;
}

static int fx_keychain_assign_stc(fx_keychain_t *kc, fx_ioctx_t *ctx) {
  int ret = 0;
  fx_field_t stc;
  if (ctx->outlet && kc->tc) {
    stc = fx_keychain_stc_make(ctx->outlet, kc->tc);
    if (fx_field_check(&stc)) {
      fx_field_free(&kc->stc);
      kc->stc = stc;
      ret = 1;
    }
  }
  return ret;
}

static fx_keychain_t *fx_keychain_new(fx_ioctx_t *ctx, fx_keychain_type type) {
  fx_keychain_t *kc = NULL;
  if (ctx && fx_keychain_type_check(type)) {
    kc = (fx_keychain_t *)calloc(1, sizeof(fx_keychain_t));
    if (kc) {
      kc->type = type;
      if (type == FX_BM_KEYCHAIN) {
        kc->pubkey = fx_field_empty(FX_FTAG_PUBKEY);
      } else if (ctx->outlet && fx_field_check(&ctx->pubkey)) {
        kc->pubkey = fx_field_clone(ctx->pubkey);
      } else {
        fx_keychain_destroy(kc);
        kc = NULL;
      }
    }
  }
  return kc;
}

fx_keychain_t *fx_keychain_create_ex(fx_ioctx_t *ctx, fx_keychain_type type,
                                     size_t n, const fx_bytes_t list[]) {
  fx_keychain_t *kc = NULL;
  fx_chunk_t *clist = NULL;
  fx_bytes_t rtc = fx_bytes_empty(), ptc = fx_bytes_empty(),
             k = fx_bytes_empty();
  kc = fx_keychain_new(ctx, type);
  if (!kc)
    goto end;

  clist = fx_chunk_pack_arr(n, list);
  ptc = fx_chunk_flat(clist);
  if (!fx_bytes_check(&ptc))
    goto end;

  // if (type == FX_AUC_KEYCHAIN) {
  // if (!ctx->outlet)
  // } else if (type == FX_KMC_KEYCHAIN) {
  // }

  // cleanup:

end:
  fx_bytes_free(&rtc);
  fx_bytes_free(&ptc);
  if (clist)
    fx_chunk_free(clist);

  return kc;
}

fx_keychain_t *fx_keychain_create2(fx_ioctx_t *ctx, fx_keychain_type type,
                                   size_t n, ...) {}

void fx_keychain_destroy(fx_keychain_t *kc) {
  if (kc) {
    if (kc->tc)
      fx_chunk_free(kc->tc);
    if (fx_field_check(&kc->stc))
      fx_field_free(&kc->stc);
    if (fx_field_check(&kc->pubkey))
      fx_field_free(&kc->pubkey);
    free(kc);
  }
}

fx_keychain_type fx_keychain_get_type(fx_keychain_t *kc) {
  return kc && fx_keychain_type_check(kc->type) ? kc->type
                                                : FX_UNKNOWN_KEYCHAIN;
}

fx_bytes_t fx_keychain_get_kte(fx_keychain_t *kc) {
  return (kc && kc->tc && kc->type == FX_AUC_KEYCHAIN)
             ? fx_chunk_get(kc->tc, fx_chunk_get_size(kc->tc) - 1)
             : fx_bytes_empty();
}

fx_bytes_t fx_keychain_get_kek(fx_keychain_t *kc) {
  return (kc && kc->tc && kc->type == FX_KMC_KEYCHAIN)
             ? fx_chunk_get(kc->tc, fx_chunk_get_size(kc->tc) - 1)
             : fx_bytes_empty();
}

fx_bytes_t fx_keychain_encode(fx_keychain_t *kc) {}

fx_keychain_t *fx_keychain_decode(fx_bytes_t data) {}

int fx_ioctx_import_keychain(fx_ioctx_t *ctx, fx_keychain_t *kc) {}

fx_keychain_t *fx_ioctx_export_keychain(fx_ioctx_t *ctx,
                                        fx_keychain_type type) {}
