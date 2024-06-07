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

#include "fx/outlet.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "skfapi.h"

#define FX_MAX_PIN_RETRIES 10
#define FX_MAX_AUTH_LEN 16
#define FX_MAX_AUTH_RAND_LEN 8
#define FX_MAX_SM3_LEN 32

#define FX_DEDUP_VAR(v) _##v

#pragma mark - fx_port_t marco
#define FX_PORT_OP_FNAME(suffix) fx_port_##suffix

#define FX_PORT_OP_DECLARE(suffix)                                             \
  int FX_PORT_OP_FNAME(suffix)(fx_port_t * port)

#define FX_PORT_OP_DECLARE_ALL(name)                                           \
  FX_PORT_OP_DECLARE(name##_add);                                              \
  FX_PORT_OP_DECLARE(name##_remove);                                           \
  FX_PORT_OP_DECLARE(name##_open);                                             \
  FX_PORT_OP_DECLARE(name##_close)

#define FX_PORT_OP_BIND(port, add_fn, remove_fn, open_fn, close_fn)            \
  do {                                                                         \
    (port)->add = (add_fn);                                                    \
    (port)->remove = (remove_fn);                                              \
    (port)->open = (open_fn);                                                  \
    (port)->close = (close_fn);                                                \
  } while (0)

#define FX_PORT_OP_BIND_ALL(port, suffix)                                      \
  FX_PORT_OP_BIND(                                                             \
      port, FX_PORT_OP_FNAME(suffix##_add), FX_PORT_OP_FNAME(suffix##_remove), \
      FX_PORT_OP_FNAME(suffix##_open), FX_PORT_OP_FNAME(suffix##_close))

#pragma mark - fx_port_list_t marco
#define FX_PLIST_ITER_FNAME(suffix) fx_port_list_##suffix##_iter

#define FX_PLIST_ITER_DECLARE(suffix)                                          \
  int FX_PLIST_ITER_FNAME(suffix)(fx_port_list_t * plist)

#define FX_PLIST_ITER(plist, obj, ret, fn)                                     \
  do {                                                                         \
    fx_bytes_free(&(plist)->raw);                                              \
    ret = fn((obj), NULL, (ULONG *)&(plist)->raw.len);                         \
    if (ret != SAR_OK || (plist)->raw.len == 0) {                              \
      (plist)->raw.len = 0;                                                    \
      break;                                                                   \
    }                                                                          \
    (plist)->raw = fx_bytes_calloc((plist)->raw.len);                          \
    if (!fx_bytes_check(&(plist)->raw))                                        \
      break;                                                                   \
    ret = fn((obj), (plist)->raw.ptr, (ULONG *)&(plist)->raw.len);             \
    if (ret == SAR_OK && fx_bytes_check(&(plist)->raw))                        \
      ret = 1;                                                                 \
  } while (0)

#define FX_PLIST_ITER_IMPL(suffix, fn, obj)                                    \
  FX_PLIST_ITER_DECLARE(suffix) {                                              \
    int ret = SAR_OK;                                                          \
    FX_PLIST_ITER(plist, obj, ret, fn);                                        \
    return ret;                                                                \
  }

#pragma mark - typealias
typedef HANDLE fx_raw_port_t;
typedef DEVHANDLE fx_dev_t;
typedef HAPPLICATION fx_app_t;
typedef HCONTAINER fx_conta_t;

typedef BLOCKCIPHERPARAM fx_cipher_ctx_t;

#pragma mark - fx_port_t
typedef int (*fx_port_op_fn)(fx_port_t *);
typedef enum {
  FX_PS_WAIT = 0,
  FX_PS_RUNNING,
  FX_PS_FINISHED,
} fx_port_stat;

FX_PORT_OP_DECLARE(dev_open);
FX_PORT_OP_DECLARE(dev_close);
FX_PORT_OP_DECLARE_ALL(app);
FX_PORT_OP_DECLARE_ALL(conta);

static inline int fx_port_type_check(fx_port_type type) {
  return (type > FX_DEFAULT_PORT) && (type < FX_MAX_PORT);
}
struct fx_port {
  fx_port_type type;
  fx_bytes_t name;
  volatile fx_port_stat stat;
  int flags;

  fx_obj_t **raw, *obj;

  fx_port_op_fn add;
  fx_port_op_fn remove;
  fx_port_op_fn open;
  fx_port_op_fn close;

  fx_outlet_t *outlet;
};

static inline void fx_port_op_bind(fx_port_t *port) {
  switch (port->type) {
  case FX_DEV_PORT:
    FX_PORT_OP_BIND(port, NULL, NULL, FX_PORT_OP_FNAME(dev_open),
                    FX_PORT_OP_FNAME(dev_close));
    break;

  case FX_APP_PORT:
    FX_PORT_OP_BIND_ALL(port, app);
    break;

  case FX_CONTA_PORT:
    FX_PORT_OP_BIND_ALL(port, conta);
    break;

  default:
    break;
  }
}

fx_port_t *fx_port_new(fx_port_type type, fx_bytes_t name, int flags,
                       fx_outlet_t *outlet, fx_obj_t *obj) {
  fx_port_t *port = NULL;
  if (!fx_port_type_check(type) || (flags & ~FX_PF_VALID_FLAGS))
    goto end;

  port = (fx_port_t *)calloc(1, sizeof(fx_port_t));
  if (!port)
    goto end;

  port->raw = (fx_obj_t *)calloc(1, sizeof(fx_obj_t *));
  if (!port->raw)
    goto err;

  port->outlet = outlet;
  port->flags = flags;
  port->type = type;
  port->obj = obj;
  port->stat = FX_PS_WAIT;
  fx_port_op_bind(port);
  port->name = fx_bytes_clone(name);
  if (port->name.len == 0)
    goto err;

  if (flags & FX_PF_OPEN) {
    flags = fx_port_open(port);
    if (flags == 1) {
      port->flags &= ~FX_PF_CREAT;
      goto end;
    } else if ((port->flags & FX_PF_CREAT) && port->add) {
      flags = port->add(port);
      if (flags == 1) {
        port->stat = FX_PS_RUNNING;
        goto end;
      } else {
        port->flags &= ~FX_PF_CREAT;
      }
    }
  }

err:
  fx_port_free(port);
  port = NULL;

end:
  return port;
}

void fx_port_free(fx_port_t *port) {
  if (port) {
    if (port->raw) {
      fx_port_close(port);

      if ((port->flags & FX_PF_CREAT) && port->remove) {
        port->remove(port);
        port->flags &= ~FX_PF_CREAT;
      }

      free(port->raw);
    }

    fx_bytes_free(&port->name);
    free(port);
  }
}

int fx_port_busy(fx_port_t *port) {
  return port && (port->stat == FX_PS_RUNNING);
}

fx_obj_t **fx_port_export(fx_port_t *port) {
  return port ? port->raw : (fx_obj_t **)NULL;
}

int fx_port_open(fx_port_t *port) {
  int ret = 0;
  if (port && port->open && !fx_port_busy(port)) {
    ret = port->open(port);
    if (ret == 1)
      port->stat = FX_PS_RUNNING;
  }

  return ret;
}

int fx_port_close(fx_port_t *port) {
  int ret = 0;
  if (port && port->close && fx_port_busy(port)) {
    ret = port->close(port);
    if (ret == 1)
      port->stat = FX_PS_FINISHED;
  }

  return ret;
}

static inline fx_obj_t **fx_port_export_oport(fx_port_t *port,
                                              fx_port_type type) {
  fx_obj_t **oport = NULL;
  if (port->outlet && fx_port_type_check(type))
    oport = fx_outlet_export(port->outlet, type);

  if (!oport && port->obj)
    oport = port->obj;

  return oport;
}

static inline fx_obj_t **fx_port_validate_oport(fx_port_t *port,
                                                fx_port_type type) {
  fx_obj_t **obj = fx_port_export_oport(port, type);
  return obj && (fx_outlet_validate_port(port->outlet, type) == 1)
             ? obj
             : (fx_obj_t **)NULL;
}

#pragma mark - fx_port_dev impl.
FX_PORT_OP_DECLARE(dev_open) {
  int ret = SKF_ConnectDev(port->name.ptr, port->raw);
  return ret == SAR_OK ? 1 : ret;
}

FX_PORT_OP_DECLARE(dev_close) {
  int ret = SKF_DisConnectDev(*port->raw);
  if (ret != SAR_OK)
    return ret;

  memset(port->raw, 0x00, sizeof(fx_obj_t *));
  return 1;
}

#pragma mark - fx_port_app impl.
FX_PORT_OP_DECLARE(app_add) {
  int ret = 0;
  fx_bytes_t pin = fx_bytes_empty();
  fx_dev_t **pdev = (fx_dev_t **)fx_port_validate_oport(port, FX_DEV_PORT);
  if (!pdev)
    goto end;

  pin = fx_outlet_get_pin(port->outlet);
  if (!fx_bytes_check(&pin))
    goto end;

  ret = SKF_CreateApplication(*pdev, port->name.ptr, pin.ptr,
                              FX_MAX_PIN_RETRIES, pin.ptr, FX_MAX_PIN_RETRIES,
                              SECURE_EVERYONE_ACCOUNT, port->raw);
  if (ret == SAR_OK)
    ret = 1;

  fx_bytes_free(&pin);

end:
  return ret;
}

FX_PORT_OP_DECLARE(app_remove) {
  int ret = 0;
  fx_dev_t **pdev = (fx_dev_t **)fx_port_validate_oport(port, FX_DEV_PORT);
  if (!pdev)
    goto end;

  ret = SKF_DeleteApplication(*pdev, port->name.ptr);
  if (ret == SAR_OK)
    ret = 1;

end:
  return ret;
}

FX_PORT_OP_DECLARE(app_open) {
  int ret = 0;
  fx_dev_t **pdev = (fx_dev_t **)fx_port_export_oport(port, FX_DEV_PORT);
  if (!pdev)
    goto end;

  ret = SKF_OpenApplication(*pdev, port->name.ptr, port->raw);
  if (ret == SAR_OK)
    ret = 1;

end:
  return ret;
}

FX_PORT_OP_DECLARE(app_close) {
  int ret = SKF_CloseApplication(*port->raw);
  return ret == SAR_OK ? 1 : ret;
}

#pragma mark - fx_port_conta impl.
FX_PORT_OP_DECLARE(conta_add) {
  int ret = 0;
  fx_app_t **papp = (fx_app_t **)fx_port_validate_oport(port, FX_APP_PORT);
  if (!papp)
    goto end;

  ret = SKF_CreateContainer(*papp, port->name.ptr, port->raw);
  if (ret == SAR_OK)
    ret = 1;

end:
  return ret;
}

FX_PORT_OP_DECLARE(conta_remove) {
  int ret = 0;
  fx_app_t **papp = (fx_app_t **)fx_port_validate_oport(port, FX_APP_PORT);
  if (!papp)
    goto end;

  ret = SKF_DeleteContainer(*papp, port->name.ptr);
  if (ret == SAR_OK)
    ret = 1;

end:
  return ret;
}

FX_PORT_OP_DECLARE(conta_open) {
  int ret = 0;
  fx_app_t **papp = (fx_app_t **)fx_port_export_oport(port, FX_APP_PORT);
  if (!papp)
    goto end;

  ret = SKF_OpenContainer(*papp, port->name.ptr, port->raw);
  if (ret == SAR_OK)
    ret = 1;

end:
  return ret;
}

FX_PORT_OP_DECLARE(conta_close) {
  int ret = SKF_CloseContainer(*port->raw);
  return ret == SAR_OK ? 1 : ret;
}

#pragma mark - fx_port_list_t
typedef int (*fx_port_list_iter_fn)(fx_port_list_t *);

struct fx_port_list {
  fx_port_type type;
  fx_bytes_t raw;

  size_t *p_offsets;
  size_t offlen;

  fx_obj_t *obj;

  fx_port_list_iter_fn iter;
};

static inline FX_PLIST_ITER_IMPL(dev, SKF_EnumDev, true);
static inline FX_PLIST_ITER_IMPL(app, SKF_EnumApplication,
                                 *(fx_dev_t *)plist->obj);
static inline FX_PLIST_ITER_IMPL(conta, SKF_EnumContainer,
                                 *(fx_app_t *)plist->obj);

static inline fx_port_list_iter_fn fx_port_list_iter_bind(fx_port_type type) {
  switch (type) {
  case FX_DEV_PORT:
    return fx_port_list_dev_iter;
  case FX_APP_PORT:
    return fx_port_list_app_iter;
  case FX_CONTA_PORT:
    return fx_port_list_conta_iter;
  default:
    return (fx_port_list_iter_fn)NULL;
  }
}

static void fx_port_list_free_offsets(fx_port_list_t *plist) {
  if (plist->p_offsets) {
    free(plist->p_offsets);
    plist->p_offsets = NULL;
    plist->offlen = 0;
  }
}

static int fx_port_list_reload(fx_port_list_t *plist) {
  int ret = 0;
  if (!fx_bytes_check(&plist->raw) &&
      (!plist->iter || plist->iter(plist) != 1 || !fx_bytes_check(&plist->raw)))
    goto end;

  fx_port_list_free_offsets(plist);
  for (size_t i = 0; i < plist->raw.len; ++i)
    if (*(plist->raw.ptr + i) == '\0') {
      plist->offlen++;
      if (i + 1 < plist->raw.len && *(plist->raw.ptr + i + 1) == '\0')
        break;
    }

  if (plist->offlen) {
    plist->p_offsets = (size_t *)calloc(sizeof(size_t), plist->offlen);
    if (!plist->p_offsets)
      goto end;

    for (size_t i = 0, j = 0; i < plist->raw.len; ++i)
      if (*(plist->raw.ptr + i) == '\0') {
        if (i + 1 < plist->raw.len && *(plist->raw.ptr + i + 1) == '\0')
          break;
        plist->p_offsets[++j] = i + 1;
      }

    ret = 1;
  }

end:
  return ret;
}

fx_port_list_t *fx_port_list_new(fx_port_type type, fx_obj_t *obj) {
  fx_port_list_t *plist = NULL;
  if (!fx_port_type_check(type))
    goto end;

  plist = (fx_port_list_t *)calloc(1, sizeof(fx_port_list_t));
  if (plist) {
    plist->obj = obj;
    plist->iter = fx_port_list_iter_bind(plist->type = type);
    if (!plist->iter || plist->iter(plist) != 1 ||
        fx_port_list_reload(plist) != 1) {
      fx_port_list_free(plist);
      plist = NULL;
    }
  }

end:
  return plist;
}

void fx_port_list_free(fx_port_list_t *plist) {
  if (plist) {
    fx_port_list_free_offsets(plist);
    fx_bytes_free(&plist->raw);
    free(plist);
  }
}

size_t fx_port_list_size(fx_port_list_t *plist) {
  return plist ? plist->offlen : 0;
}

static inline size_t fx_port_list_get_name_size(fx_port_list_t *plist,
                                                size_t idx) {
  size_t *poffset = plist->p_offsets + idx;
  return (idx + 1 < plist->offlen) ? (*(poffset + 1) - *poffset)
                                   : (plist->raw.len - 1 - *poffset);
}

static inline const uint8_t *
fx_port_list_peek_name_ex(fx_port_list_t *plist, size_t idx, size_t *nlen) {
  if (nlen)
    *nlen = fx_port_list_get_name_size(plist, idx);
  return plist->raw.ptr + *(plist->p_offsets + idx);
}

static inline fx_bytes_t fx_port_list_get_name_ex(fx_port_list_t *plist,
                                                  size_t idx) {
  size_t len = 0;
  const uint8_t *pname = fx_port_list_peek_name_ex(plist, idx, &len);
  return (pname && len) ? fx_bytes_clone(fx_bytes_new((uint8_t *)pname, len))
                        : fx_bytes_empty();
}

const char *fx_port_list_peek_name2char(fx_port_list_t *plist, size_t idx,
                                        size_t *nlen) {
  return (plist && idx < plist->offlen)
             ? (const char *)fx_port_list_peek_name_ex(plist, idx, nlen)
             : (const char *)NULL;
}

fx_bytes_t fx_port_list_get_name(fx_port_list_t *plist, size_t idx) {
  fx_bytes_t name = fx_bytes_empty();
  if (plist && idx < plist->offlen)
    name = fx_port_list_get_name_ex(plist, idx);

  return name;
}

int fx_port_list_export2char(fx_port_list_t *plist, char **list, size_t *nlen) {
  int ret = 0;
  fx_bytes_t name;
  if (!plist)
    goto end;

  if (list) {
    if (!nlen || !*nlen)
      goto end;

    for (size_t i = 0, j = 0; i < plist->offlen; ++i) {
      name = fx_port_list_get_name_ex(plist, i);
      if (!fx_bytes_check(&name))
        goto cleanup;
      *(list + i) = (char *)name.ptr;
    }

    ret = 1;
    goto end;
  } else if (nlen) {
    *nlen = plist->offlen;
    ret = 1;
    goto end;
  }

cleanup:
  for (size_t i = 0; i < plist->offlen; ++i)
    if (*(list + i)) {
      free(*(list + i));
      *(list + i) = NULL;
    }

  ret = 0;

end:
  return ret;
}

#pragma mark - fx_outlet_t
struct fx_outlet {
  fx_bytes_t pin;
  fx_bytes_t authkey;
  fx_bytes_t auth;

  fx_port_t *pdev, *papp, *pconta;
};

static int fx_outlet_gen_auth(fx_outlet_t *outlet, fx_dev_t **pdev) {
  int ret = 0;
  fx_raw_port_t pkey = NULL;
  fx_cipher_ctx_t cctx = {0};
  fx_bytes_t block = fx_bytes_calloc(FX_MAX_AUTH_LEN);
  if (!outlet->pdev || !fx_port_busy(outlet->pdev) ||
      !fx_bytes_check(&outlet->authkey) || !fx_bytes_check(&block))
    goto end;

    fx_bytes_free(&outlet->auth);

  outlet->auth = fx_bytes_calloc(FX_MAX_AUTH_LEN);
  if (!fx_bytes_check(&outlet->auth))
    goto err;

  ret = SKF_GenRandom(*pdev, block.ptr, FX_MAX_AUTH_RAND_LEN);
  if (ret != SAR_OK)
    goto err;

  ret = SKF_SetSymmKey(*pdev, outlet->authkey.ptr, SGD_SM4_ECB, &pkey);
  if (ret != SAR_OK)
    goto err;

  ret = SKF_EncryptInit(pkey, cctx);
  if (ret != SAR_OK)
    goto err;

  ret = SKF_Encrypt(pkey, block.ptr, block.len, outlet->auth.ptr,
                    (ULONG *)&outlet->auth.len);
  if (ret == SAR_OK) {
    fx_bytes_free(&block);
    ret = 1;
    goto end;
  }

err:
  fx_bytes_free(&outlet->auth);
  fx_bytes_free(&block);

end:
  return ret;
}

static int fx_outlet_unlock_dev(fx_outlet_t *outlet) {
  int ret = 0;
  fx_dev_t **pdev = (fx_dev_t **)fx_port_export(outlet->pdev);

  if (!pdev)
    goto end;

  if (!fx_bytes_check(&outlet->auth)) {
    ret = fx_outlet_gen_auth(outlet, pdev);
    if (ret != 1)
      goto end;
  }

  ret = SKF_DevAuth(*pdev, outlet->auth.ptr, outlet->auth.len);
  if (ret == SAR_OK)
    ret = 1;
  else
    fx_bytes_free(&outlet->auth);

end:
  return ret;
}

static int fx_outlet_unlock_conta(fx_outlet_t *outlet) {
  int ret = 0;
  size_t retries = 0;
  fx_app_t **papp = (fx_app_t **)fx_port_export(outlet->papp);

  if (!papp || !fx_bytes_check(&outlet->pin))
    goto end;

  ret = SKF_VerifyPIN(*papp, USER_TYPE, outlet->pin.ptr, (ULONG *)&retries);
  if (ret == SAR_OK) {
    ret = 1;
    goto end;
  } else {
    ret = SKF_VerifyPIN(*papp, ADMIN_TYPE, outlet->pin.ptr, (ULONG *)&retries);
    if (ret == SAR_OK)
      ret = 1;
  }

end:
  return ret;
}

fx_outlet_t *fx_outlet_new(const char *authkey, const char *pin) {
  fx_outlet_t *outlet = NULL;
  if (!authkey || !pin)
    goto end;

  outlet = (fx_outlet_t *)calloc(1, sizeof(fx_outlet_t));
  if (!outlet)
    goto end;

  outlet->auth = fx_bytes_empty();
  outlet->pin = fx_bytes_clone(fx_bytes_new((uint8_t *)pin, strlen(pin) + 1));
  outlet->authkey =
      fx_bytes_clone(fx_bytes_new((uint8_t *)authkey, strlen(authkey) + 1));
  if (!fx_bytes_check(&outlet->pin) || !fx_bytes_check(&outlet->authkey)) {
    fx_outlet_free(outlet);
    outlet = NULL;
  }

end:
  return outlet;
}

void fx_outlet_free(fx_outlet_t *outlet) {
  if (outlet) {
    fx_outlet_validate_port(outlet, FX_APP_PORT);
    fx_port_free(outlet->pconta);

    fx_outlet_validate_port(outlet, FX_DEV_PORT);
    fx_port_free(outlet->papp);

    fx_port_free(outlet->pdev);

    fx_bytes_free(&outlet->auth);
    fx_bytes_free(&outlet->authkey);
    fx_bytes_free(&outlet->pin);
    free(outlet);
  }
}

const char *fx_outlet_peek_pin2char(fx_outlet_t *outlet) {
  return (const char *)(outlet ? outlet->pin.ptr : NULL);
}

fx_bytes_t fx_outlet_get_pin(fx_outlet_t *outlet) {
  return outlet ? fx_bytes_clone(outlet->pin) : fx_bytes_empty();
}

fx_obj_t **fx_outlet_export(fx_outlet_t *outlet, fx_port_type type) {
  fx_port_t *port = NULL;
  if (outlet)
    switch (type) {
    case FX_DEV_PORT:
      port = outlet->pdev;
      break;

    case FX_APP_PORT:
      port = outlet->papp;
      break;

    case FX_CONTA_PORT:
      port = outlet->pconta;
      break;

    default:
      break;
    }

  return fx_port_export(port);
}

int fx_outlet_set_port(fx_outlet_t *outlet, fx_port_type type,
                       fx_port_t *port) {
  if (outlet && fx_port_busy(port) == 1) {
    switch (type) {
    case FX_DEV_PORT:
      outlet->pdev = port;
      break;

    case FX_APP_PORT:
      outlet->papp = port;
      break;

    case FX_CONTA_PORT:
      outlet->pconta = port;
      break;

    default:
      goto end;
    }

    port->outlet = outlet;
    return 1;
  }

end:
  return 0;
}

int fx_outlet_validate_port(fx_outlet_t *outlet, fx_port_type type) {
  if (outlet)
    switch (type) {
    case FX_DEV_PORT:
      return fx_outlet_unlock_dev(outlet);
    case FX_APP_PORT:
      return fx_outlet_unlock_conta(outlet);
    default:
      break;
    }

  return 0;
}

#pragma mark - crypto
#define FX_OUTLET_GEN_BYTES_DECLARE(name)                                      \
  int fx_outlet_gen_##name##_impl(fx_outlet_t *outlet, fx_port_type type,      \
                                  fx_obj_t **port, fx_bytes_t in,              \
                                  fx_bytes_t *out, fx_obj_t *obj)

typedef int (*fx_outlet_gen_bytes_fn)(fx_outlet_t *, fx_port_type, fx_obj_t **,
                                      fx_bytes_t, fx_bytes_t *, fx_obj_t *);

static fx_bytes_t fx_outlet_gen_bytes(fx_outlet_t *outlet, fx_port_type type,
                                      fx_bytes_t in, size_t olen, int validate,
                                      fx_obj_t *obj,
                                      fx_outlet_gen_bytes_fn fn) {
  int ret = 0;
  fx_bytes_t out = fx_bytes_empty();
  fx_obj_t **port = fx_outlet_export(outlet, type);
  if (fn && port && *port) {
    if (!!validate && fx_port_type_check(type) && type != FX_DEV_PORT)
      fx_outlet_validate_port(outlet, type - 1);

    if (olen) {
      out = fx_bytes_calloc(olen);
      if (!fx_bytes_check(&out))
        goto end;
    }

    ret = fn(outlet, type, port, in, &out, obj);
    if (ret != 1)
      fx_bytes_free(&out);
  }

end:
  return out;
}

static inline FX_OUTLET_GEN_BYTES_DECLARE(ecckey) {
  int ret = SKF_GenECCKeyPair(*(fx_conta_t **)port, SGD_SM2_1,
                              (ECCPUBLICKEYBLOB *)out->ptr);
  return ret == SAR_OK ? 1 : ret;
}

fx_bytes_t fx_outlet_gen_ecckey(fx_outlet_t *outlet) {
  return fx_outlet_gen_bytes(outlet, FX_CONTA_PORT, fx_bytes_empty(),
                             sizeof(ECCPUBLICKEYBLOB), 1, NULL,
                             fx_outlet_gen_ecckey_impl);
}

static inline FX_OUTLET_GEN_BYTES_DECLARE(random) {
  int ret = SKF_GenRandom(*(fx_dev_t **)port, out->ptr, out->len);
  return ret == SAR_OK ? 1 : ret;
}

fx_bytes_t fx_outlet_gen_random(fx_outlet_t *outlet, size_t len) {
  return fx_outlet_gen_bytes(outlet, FX_DEV_PORT, fx_bytes_empty(), len, 0,
                             NULL, fx_outlet_gen_random_impl);
}

static inline FX_OUTLET_GEN_BYTES_DECLARE(ecc_sign) {
  int ret = SKF_ECCSignData(*(fx_conta_t **)port, in.ptr, in.len,
                            (PECCSIGNATUREBLOB)out->ptr);
  return ret == SAR_OK ? 1 : ret;
}

fx_bytes_t fx_outlet_ecc_sign(fx_outlet_t *outlet, fx_bytes_t in, int preproc) {
  fx_bytes_t procin = fx_bytes_empty();
  if (preproc)
    procin = fx_outlet_sm3_digest(outlet, in);

  in = fx_outlet_gen_bytes(outlet, FX_CONTA_PORT, procin,
                           sizeof(ECCSIGNATUREBLOB), 0, NULL,
                           fx_outlet_gen_ecc_sign_impl);
  if (preproc)
    fx_bytes_free(&procin);

  return in;
}

static FX_OUTLET_GEN_BYTES_DECLARE(sm3_digest) {
  fx_raw_port_t rport = NULL;
  int flag = !!(out->ptr),
      ret = SKF_DigestInit(*(fx_dev_t **)port, SGD_SM3, NULL, NULL, 0, &rport);
  if (ret == SAR_OK) {
    ret = SKF_Digest(rport, in.ptr, in.len, out->ptr, (ULONG *)&out->len);
    if (ret == SAR_OK && out->len) {
      if (flag) {
        ret = 1;
        goto end;
      }

      *out = fx_bytes_calloc(out->len);
      if (fx_bytes_check(out)) {
        ret = SKF_Digest(rport, in.ptr, in.len, out->ptr, (ULONG *)&out->len);
        if (ret == SAR_OK)
          ret = 1;
      }
    }
  }

end:
  return ret;
}

fx_bytes_t fx_outlet_sm3_digest(fx_outlet_t *outlet, fx_bytes_t in) {
  return fx_outlet_gen_bytes(outlet, FX_DEV_PORT, in, 0, 0, NULL,
                             fx_outlet_gen_sm3_digest_impl);
}

typedef ULONG (*fx_outlet_crypto_init_fn)(fx_raw_port_t, fx_cipher_ctx_t);
typedef ULONG (*fx_outlet_crypto_fn)(fx_raw_port_t, uint8_t *, ULONG, uint8_t *,
                                     ULONG *);
typedef struct {
  fx_cipher_type type;
  fx_bytes_t key, iv;
} fx_crypto_ctx_t;

static int fx_outlet_crypto_preproc(fx_cipher_type type, fx_obj_t **port,
                                    fx_obj_t *obj, fx_raw_port_t *rport,
                                    fx_cipher_ctx_t *cctx) {
  fx_crypto_ctx_t *ctx = (fx_crypto_ctx_t *)obj;
  ULONG algo_id =
      fx_cipher_type_check(ctx->type) ? (SGD_SM4_ECB << ctx->type) : ctx->type;
  int ret = SKF_SetSymmKey(*(fx_dev_t **)port, ctx->key.ptr, algo_id, rport);
  if (ret == SAR_OK) {
    ret = 1;
    if (fx_bytes_check(&ctx->iv) && ctx->iv.len <= MAX_IV_LEN) {
      cctx->PaddingType = 1;
      cctx->IVLen = ctx->iv.len;
      memcpy(cctx->IV, ctx->iv.ptr, ctx->iv.len);
    }
  }

  return ret;
}

static int fx_outlet_gen_crypto(fx_outlet_t *outlet, fx_port_type type,
                                fx_obj_t **port, fx_bytes_t in, fx_bytes_t *out,
                                fx_obj_t *obj,
                                fx_outlet_crypto_init_fn crypto_init_fn,
                                fx_outlet_crypto_fn crypto_fn) {
  fx_raw_port_t rport = NULL;
  fx_cipher_ctx_t cctx = {0};
  int flag = !!(out->ptr),
      ret = fx_outlet_crypto_preproc(type, port, obj, &rport, &cctx);
  if (ret == 1 && crypto_init_fn) {
    ret = crypto_init_fn(rport, cctx);
    if (ret == SAR_OK && crypto_fn) {
      ret = crypto_fn(rport, in.ptr, in.len, out->ptr, (ULONG *)&out->len);
      if (ret == SAR_OK && out->len) {
        if (flag) {
          ret = 1;
          goto end;
        }

        *out = fx_bytes_calloc(out->len);
        if (fx_bytes_check(out)) {
          ret = crypto_fn(rport, in.ptr, in.len, out->ptr, (ULONG *)&out->len);
          if (ret == SAR_OK)
            ret = 1;
        }
      }
    }
  }

end:
  return ret;
}

static inline FX_OUTLET_GEN_BYTES_DECLARE(encrypt) {
  return fx_outlet_gen_crypto(outlet, type, port, in, out, obj, SKF_EncryptInit,
                              SKF_Encrypt);
}

fx_bytes_t fx_outlet_encrypt(fx_outlet_t *outlet, fx_cipher_type type,
                             fx_bytes_t key, fx_bytes_t iv, fx_bytes_t in) {
  fx_crypto_ctx_t ctx = {
      .type = type,
      .key = key,
      .iv = iv,
  };
  return fx_outlet_gen_bytes(outlet, FX_DEV_PORT, in, 0, 0, &ctx,
                             fx_outlet_gen_encrypt_impl);
}

static inline FX_OUTLET_GEN_BYTES_DECLARE(decrypt) {
  return fx_outlet_gen_crypto(outlet, type, port, in, out, obj, SKF_DecryptInit,
                              SKF_Decrypt);
}

fx_bytes_t fx_outlet_decrypt(fx_outlet_t *outlet, fx_cipher_type type,
                             fx_bytes_t key, fx_bytes_t iv, fx_bytes_t in) {
  fx_crypto_ctx_t ctx = {
      .type = type,
      .key = key,
      .iv = iv,
  };
  return fx_outlet_gen_bytes(outlet, FX_DEV_PORT, in, 0, 0, &ctx,
                             fx_outlet_gen_decrypt_impl);
}

static inline FX_OUTLET_GEN_BYTES_DECLARE(ecc_encrypt) {
  int ret = SAR_UNKNOWNERR;
  fx_bytes_t *pubkey = (fx_bytes_t *)obj;
  if (fx_bytes_check(pubkey))
    ret = SKF_ExtECCEncrypt(*(fx_dev_t **)port, (ECCPUBLICKEYBLOB *)pubkey->ptr,
                            in.ptr, in.len, (PECCCIPHERBLOB)out->ptr);
  return ret == SAR_OK ? 1 : ret;
}

fx_bytes_t fx_outlet_ecc_encrypt(fx_outlet_t *outlet, fx_bytes_t pubkey,
                                 fx_bytes_t in) {
  return fx_outlet_gen_bytes(outlet, FX_DEV_PORT, in,
                             in.len + sizeof(ECCCIPHERBLOB), 0, &pubkey,
                             fx_outlet_gen_ecc_encrypt_impl);
}