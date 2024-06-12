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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "fx/outlet.h"
#include "skfapi.h"

#define FX_MAX_K_TE_LEN 16
#define FX_MAX_KEK_LEN 16
#define FX_TC_CHUNK_IDX 0
#define FX_STC_CHUNK_IDX 1
#define FX_PUBKEY_CHUNK_IDX 2

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
  FX_FTAG_EX_ETC = 0xD003,
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
  fx_field_t pubkey, ctc;
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

static inline int fx_keychain_k_make(fx_ioctx_t *ctx, fx_keychain_type type,
                                     fx_bytes_t *k) {
  int ret = FX_MAX_KEK_LEN;
  if (ctx && k)
    switch (type) {
    case FX_AUC_KEYCHAIN:
      ret = FX_MAX_K_TE_LEN;
    case FX_KMC_KEYCHAIN:
      *k = fx_outlet_gen_random(ctx->outlet, ret);
      if (!fx_bytes_check(k))
        ret = 0;
      break;
    default:
      break;
    }
  return !!ret;
}

static inline fx_field_t fx_keychain_ctc_make(fx_keychain_t *kc,
                                              fx_ioctx_t *ctx) {
  fx_bytes_t btc = fx_bytes_empty();
  fx_field_t ctc = fx_field_empty(FX_FTAG_UNKNOWN);
  if (ctx->outlet && fx_keychain_type_check(kc->type)) {
    btc = fx_chunk_flat(kc->tc);
    if (fx_bytes_check(&btc)) {
      ctc = (kc->type == FX_BM_KEYCHAIN)
                ? fx_bytes2field(
                      FX_FTAG_EX_ETC,
                      fx_outlet_ecc_encrypt(ctx->outlet,
                                            fx_field2bytes(kc->pubkey), btc))
                : fx_bytes2field(FX_FTAG_EX_STC,
                                 fx_outlet_ecc_sign(ctx->outlet, btc, 1));
    }
    fx_bytes_free(&btc);
  }
  return ctc;
}

static int fx_keychain_assign_ctc(fx_keychain_t *kc, fx_ioctx_t *ctx) {
  int ret = 0;
  fx_field_t ctc;
  if (kc) {
    ctc = fx_keychain_ctc_make(kc, ctx);
    if (fx_field_check(&ctc)) {
      fx_field_free(&kc->ctc);
      kc->ctc = ctc;
      ret = 1;
    }
  }
  return ret;
}

static fx_keychain_t *fx_keychain_new(fx_ioctx_t *ctx, fx_keychain_type type) {
  fx_keychain_t *kc = NULL;
  if (fx_keychain_type_check(type)) {
    kc = (fx_keychain_t *)calloc(1, sizeof(fx_keychain_t));
    if (kc) {
      kc->type = type;
      if (ctx) {
        if (fx_field_check(&ctx->pubkey)) {
          kc->pubkey = fx_field_clone(ctx->pubkey);
        } else {
          fx_keychain_destroy(kc);
          kc = NULL;
        }
      }
    }
  }
  return kc;
}

static fx_keychain_t *
fx_keychain_make(fx_ioctx_t *ctx, fx_keychain_type type, size_t n, void *list,
                 void (*list_dump_fn)(fx_bytes_t *, void *list, size_t)) {
  const size_t nsize = sizeof(fx_bytes_t), asize = n * nsize;
  fx_keychain_t *kc = NULL;
  fx_bytes_t *klist = NULL;
  fx_bytes_t k = fx_bytes_empty();
  if (!n || fx_keychain_k_make(ctx, type, &k) != 1)
    goto end;

  klist = (fx_bytes_t *)malloc(asize + nsize);
  if (!klist)
    goto end;

  list_dump_fn(klist, list, n);
  if (fx_bytes_check(&k)) {
    memcpy(klist + n, &k, nsize);
    n++;
  }

  kc = fx_keychain_new(ctx, type);
  if (!kc)
    goto end;

  kc->tc = fx_chunk_pack_arr(n, klist);
  if (!kc->tc || fx_keychain_assign_ctc(kc, ctx) != 1) {
    fx_keychain_destroy(kc);
    kc = NULL;
  }

end:
  fx_bytes_free(&k);
  if (klist)
    free(klist);

  return kc;
}

static inline void fx_keychain_create_arr_list_dump(fx_bytes_t *klist,
                                                    void *list, size_t n) {
  memcpy(klist, list, n * sizeof(fx_bytes_t));
}

fx_keychain_t *fx_keychain_create_ex(fx_ioctx_t *ctx, fx_keychain_type type,
                                     size_t n, const fx_bytes_t list[]) {
  return fx_keychain_make(ctx, type, n, (void *)list,
                          fx_keychain_create_arr_list_dump);
}

static inline void fx_keychain_create_list_dump(fx_bytes_t *klist, void *list,
                                                size_t n) {
  fx_bytes_t tmp = fx_bytes_empty();
  for (size_t i = 0; i < n; ++i) {
    tmp = va_arg(*(va_list *)list, fx_bytes_t);
    memcpy(klist++, &tmp, sizeof(fx_bytes_t));
  }
}

fx_keychain_t *fx_keychain_create2(fx_ioctx_t *ctx, fx_keychain_type type,
                                   size_t n, ...) {
  fx_keychain_t *kc;
  va_list list;
  va_start(list, n);
  kc = fx_keychain_make(ctx, type, n, &list, fx_keychain_create_list_dump);
  va_end(list);
  return kc;
}

void fx_keychain_destroy(fx_keychain_t *kc) {
  if (kc) {
    if (kc->tc)
      fx_chunk_free(kc->tc);
    if (fx_field_check(&kc->ctc))
      fx_field_free(&kc->ctc);
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

fx_bytes_t fx_keychain_get(fx_keychain_t *kc, size_t idx) {
  return (kc && kc->tc && idx < fx_chunk_get_size(kc->tc))
             ? fx_chunk_get(kc->tc, idx)
             : fx_bytes_empty();
}

fx_bytes_t fx_keychain_encode(fx_keychain_t *kc) {
  int bsize = 0;
  size_t size = 0;
  fx_bytes_t data = fx_bytes_empty(), tcb = fx_bytes_empty(),
             ctc = fx_bytes_empty(), key = fx_bytes_empty();
  fx_field_t tmp = fx_field_empty(FX_FTAG_UNKNOWN);
  if (!kc || !fx_field_check(&kc->ctc) || !fx_keychain_type_check(kc->type))
    goto end;

  if (kc->type == FX_BM_KEYCHAIN) {
    tmp = kc->ctc;
    tmp.t = fx_keychain_type2tag(kc->type);
    tcb = fx_field2bytes_flat(tmp);
    tmp = fx_field_empty(FX_FTAG_UNKNOWN);
    size = Base64encode_len(tcb.len);
    if (!size || !fx_bytes_check(&tcb))
      goto end;

    data = fx_bytes_calloc(size);
    if (fx_bytes_check(&data) && Base64encode(data.ptr, tcb.ptr, tcb.len) <= 0)
      fx_bytes_free(&data);

  } else if (fx_field_check(&kc->pubkey)) {
    tmp = fx_bytes2field(FX_FTAG_EX_TC, fx_chunk_flat(kc->tc));
    if (!fx_field_check(&tmp))
      goto end;

    tcb = fx_field2bytes_flat(tmp);
    ctc = fx_field2bytes_flat(kc->ctc);
    key = fx_field2bytes_flat(kc->pubkey);
    if (!fx_bytes_check(&tcb) || !fx_bytes_check(&ctc) || !fx_bytes_check(&key))
      goto end;

    fx_field_free(&tmp);
    tmp = fx_field_calloc(fx_keychain_type2tag(kc->type),
                          tcb.len + ctc.len + key.len);
    if (!fx_field_check(&tmp))
      goto end;

    memcpy(tmp.v, tcb.ptr, tcb.len);
    memcpy(tmp.v + tcb.len, ctc.ptr, ctc.len);
    memcpy(tmp.v + tcb.len + ctc.len, key.ptr, key.len);
    fx_bytes_free(&tcb);
    tcb = fx_field2bytes_flat(tmp);
    size = Base64encode_len(tcb.len);
    if (!size || !fx_bytes_check(&tcb))
      goto end;

    data = fx_bytes_calloc(size);
    if (fx_bytes_check(&data)) {
      bsize = Base64encode(data.ptr, tcb.ptr, tcb.len);
      if (bsize <= 0)
        fx_bytes_free(&data);
    }
  }

end:
  fx_field_free(&tmp);
  fx_bytes_free(&key);
  fx_bytes_free(&ctc);
  fx_bytes_free(&tcb);

  return data;
}

fx_keychain_t *fx_keychain_decode(fx_bytes_t data) {
  int bsize = 0;
  fx_keychain_t *kc = NULL;
  fx_chunk_t *chunk = NULL;
  fx_bytes_t kcb = fx_bytes_empty();
  fx_field_t shell = fx_field_empty(FX_FTAG_UNKNOWN);
  if (!fx_bytes_check(&data) || Base64validate(data.ptr, 0) != 1)
    goto end;

  kcb.len = Base64decode_len(data.ptr);
  if (kcb.len <= 0)
    goto end;

  kcb = fx_bytes_calloc(kcb.len);
  if (!fx_bytes_check(&kcb))
    goto end;

  bsize = Base64decode(kcb.ptr, data.ptr);
  if (bsize <= kcb.len)
    kcb.len = bsize;
  else if (bsize <= 0)
    goto end;

  shell = fx_bytes2field_compact(kcb);
  if (!fx_field_check(&shell))
    goto end;

  kc = fx_keychain_new(NULL, fx_keychain_tag2type(shell.t));
  if (!kc)
    goto end;

  if (kc->type == FX_BM_KEYCHAIN) {
    kc->ctc = fx_field_clone(shell);
    kc->ctc.t = FX_FTAG_EX_ETC;
    goto end;
  } else if (fx_keychain_type_check(kc->type)) {
    chunk = fx_chunk_compact(kcb);
    if (!chunk)
      goto end;

    kc->pubkey = fx_bytes2field_clone(
        FX_FTAG_PUBKEY, fx_chunk_peek(chunk, FX_PUBKEY_CHUNK_IDX));
    kc->ctc = fx_bytes2field_clone(FX_FTAG_EX_STC,
                                   fx_chunk_peek(chunk, FX_STC_CHUNK_IDX));
    kc->tc = fx_chunk_compact(fx_chunk_peek(chunk, FX_TC_CHUNK_IDX));
    if (!kc->tc || !fx_field_check(&kc->ctc) || !fx_field_check(&kc->pubkey)) {
      fx_keychain_destroy(kc);
      kc = NULL;
    }
  }

end:
  if (chunk)
    fx_chunk_free(chunk);

  fx_field_free(&shell);
  fx_bytes_free(&kcb);

  return kc;
}

typedef struct fx_key_name {
  int valid;
  uint8_t name[MAX_FILE_NAME_LEN];
} fx_keyname_t;

static fx_keyname_t keynames[FX_MAX_KEYCHAIN] = {0};

static inline fx_keyname_t *fx_keyname_get_ex(fx_keychain_type type) {
  return keynames + ((int)type - 1);
}

static fx_bytes_t fx_keyname_gen(fx_outlet_t *outlet, fx_keychain_type type) {
  fx_bytes_t file = fx_bytes_empty();
  uint8_t tmp[strlen("0x000") + 1];
  if (!fx_keychain_type_check(type))
    goto end;

  if (sprintf(tmp, "0x%03X", type << FX_MAX_KEYCHAIN) <= 0)
    goto end;

  file.ptr = tmp;
  file.len = strlen(file.ptr);
  file = fx_outlet_sm3_digest(outlet, file);
  if (!fx_bytes_check(&file) || file.len > MAX_FILE_NAME_LEN)
    goto end;

  for (size_t i = 0; i < file.len; ++i)
    sprintf(fx_keyname_get_ex(type)->name + (i * 2), "%02X", *(file.ptr + i));
  *(fx_keyname_get_ex(type)->name + file.len - 1) = '\0';
  fx_keyname_get_ex(type)->valid = 1;
  fx_bytes_free(&file);
  file = fx_bytes_new(fx_keyname_get_ex(type)->name, MAX_FILE_NAME_LEN);

end:
  return file;
}

static inline fx_bytes_t fx_keyname_get(fx_outlet_t *outlet,
                                        fx_keychain_type type) {
  return fx_keychain_type_check(type) && fx_keyname_get_ex(type)->valid
             ? fx_bytes_new(fx_keyname_get_ex(type)->name, MAX_FILE_NAME_LEN)
             : fx_keyname_gen(outlet, type);
}

int fx_ioctx_import(fx_ioctx_t *ctx, fx_keychain_type type, fx_bytes_t data) {
  int ret = 0, flag = 0;
  fx_port_t *port;
  fx_bytes_t filename = fx_bytes_empty();
  if (!ctx)
    goto end;

  filename = fx_keyname_get(ctx->outlet, type);
  if (!fx_bytes_check(&filename))
    goto end;

  if (fx_outlet_file_exist(ctx->outlet, filename)) {
    port = fx_outlet_export_port(ctx->outlet, FX_FILE_PORT);
    if (port)
      goto do_import;

    port = fx_port_new(FX_FILE_PORT, filename, FX_PF_OPEN, ctx->outlet,
                       fx_outlet_export(ctx->outlet, FX_APP_PORT));
    if (port && fx_outlet_set_port(ctx->outlet, FX_FILE_PORT, port) == 1)
      flag = 1;
  } else {
    ret = fx_outlet_create_file(ctx->outlet, filename);
    flag = ret;
  }

do_import:
  ret = fx_outlet_fswrite(ctx->outlet, data, 0);

end:
  if (!!flag)
    fx_outlet_set_port(ctx->outlet, FX_FILE_PORT, NULL);

  return ret;
}

fx_bytes_t fx_ioctx_export(fx_ioctx_t *ctx, fx_keychain_type type) {
  int flag = 0;
  fx_bytes_t file = fx_bytes_empty();
  fx_port_t *port;
  if (!ctx)
    goto end;

  file = fx_keyname_get(ctx->outlet, type);
  if (!fx_bytes_check(&file) || !fx_outlet_file_exist(ctx->outlet, file))
    goto end;

  port = fx_outlet_export_port(ctx->outlet, FX_FILE_PORT);
  if (!port) {
    port = fx_port_new(FX_FILE_PORT, file, FX_PF_OPEN, ctx->outlet,
                       fx_outlet_export(ctx->outlet, FX_APP_PORT));
    if (!port)
      goto end;

    flag = fx_outlet_set_port(ctx->outlet, FX_FILE_PORT, port);
  }

  file.len = fx_outlet_file_size(ctx->outlet, file);
  if (file.len)
    file = fx_outlet_fsread(ctx->outlet, file.len, 0);

end:
  if (!!flag)
    fx_outlet_set_port(ctx->outlet, FX_FILE_PORT, NULL);

return file;
}