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

#include "fx/utils.h"
#include "skfapi.h"

#define FX_PIN_RETRY_TIMES 10
#define FX_MAX_AUTH_LEN 16

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
typedef DEVHANDLE fx_dev_t;
typedef HAPPLICATION fx_app_t;
typedef HCONTAINER fx_conta_t;

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
                       fx_obj_t *obj) {
  fx_port_t *port = NULL;
  if (!fx_port_type_check(type) || (flags & ~FX_PF_VALID_FLAGS))
    goto end;

  port = (fx_port_t *)calloc(1, sizeof(fx_port_t));
  if (!port)
    goto end;

  port->raw = (fx_obj_t *)calloc(1, sizeof(fx_obj_t *));
  if (!port->raw)
    goto err;

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
    } else if ((flags & FX_PF_CREAT) && port->add) {
      flags = port->add(port);
      if (flags == 1)
        goto end;
      else
        port->flags &= ~FX_PF_CREAT;
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

      if ((port->flags & FX_PF_CREAT) && port->remove)
        port->remove(port);

      free(port->raw);
    }

    fx_bytes_free(&port->name);
    free(port);
  }
}

int fx_port_busy(fx_port_t *port) {
  return port && (port->stat == FX_PS_RUNNING);
}

fx_obj_t *fx_port_export(fx_port_t *port) {
  return port ? port->raw : (fx_obj_t *)NULL;
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

#pragma mark - fx_port_dev impl.
FX_PORT_OP_DECLARE(dev_open) {
  int ret = SKF_ConnectDev(port->name.ptr, port->raw);
  return ret == SAR_OK ? ret == SAR_OK : ret;
}

FX_PORT_OP_DECLARE(dev_close) {
  int ret = SKF_DisConnectDev(*port->raw);
  if (ret != SAR_OK)
    return ret;

  memset(port->raw, 0x00, sizeof(fx_obj_t *));
  return 1;
}

#pragma mark - fx_port_app impl.
FX_PORT_OP_DECLARE(app_add) { return 0; }
FX_PORT_OP_DECLARE(app_remove) { return 0; }
FX_PORT_OP_DECLARE(app_open) { return 0; }
FX_PORT_OP_DECLARE(app_close) { return 0; }

#pragma mark - fx_port_conta impl.
FX_PORT_OP_DECLARE(conta_add) { return 0; }
FX_PORT_OP_DECLARE(conta_remove) { return 0; }
FX_PORT_OP_DECLARE(conta_open) { return 0; }
FX_PORT_OP_DECLARE(conta_close) { return 0; }

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

// fx_raw_layers_t *fx_raw_layers_new(size_t len) {
//   fx_raw_layers_t *plist = (fx_raw_layers_t
//   *)malloc(sizeof(fx_raw_layers_t)); if (plist) {
//     plist->list = (fx_bytes_t *)calloc(sizeof(fx_bytes_t), len);
//     if (!plist->list) {
//       fx_port_list_free(plist);
//       plist = NULL;
//     } else {
//       plist->len = len;
//     }
//   }

//   return plist;
// }

// void fx_port_list_free(fx_port_list_t *plist) {
//   if (plist) {
//     if (plist->list) {
//       if (plist->len != 0) {
//         for (size_t i = 0; i < plist->len; ++i)
//           fx_bytes_free(plist->list + i);
//         plist->len = 0;
//       }
//       free(plist->list);
//       plist->list = NULL;
//     }
//     free(plist);
//   }
// }

// size_t fx_raw_layers_get_list(fx_raw_layers_t *raw_layers,
//                               const uint8_t **bufs) {}

// static int fx_raw_layers_load_ex(fx_raw_layers_t *raw_layers,
//                                  fx_port_list_iter_fn iter, fx_obj_t *obj)
//                                  {
//   int ret = 0;
//   fx_bytes_t raw_bytes = fx_bytes_empty();

//   ret = iter(&raw_bytes, obj);
//   if (ret != 1)
//     goto end;

// end:
//   return ret;
// }

// struct port *init_layer(xulong nlen) {
//   struct port *la = NULL;

//   if ((nlen == 0) ||
//       (IS_NULL(la) &&
//        IS_NULL(la = (struct port *)malloc(sizeof(struct port)))) ||
//       (IS_NULL(la->name = (xchar *)malloc(sizeof(xchar) * nlen))))
//     XPERR_RT("failed to init port.", la);

//   memset(la->name, '\0', sizeof(xchar) * nlen);
//   la->size = nlen;

//   return la;
// }

// void free_layer(struct port *la) {
//   if (IS_NULL(la))
//     return;

//   if (!IS_NULL(la->name))
//     free(la->name);

//   free(la);
// }

// struct layer_list *init_layer_list(xulong nlen) {
//   struct layer_list *list = NULL;

//   if ((nlen == 0) ||
//       IS_NULL(list = (struct layer_list *)malloc(sizeof(struct
//       layer_list))))
//     goto err;

//   memset(list, '\0', sizeof(struct layer_list));

//   if (IS_NULL(list->plist =
//                   (struct port **)malloc(sizeof(struct port *) * nlen))) {
//     free_layer_list(list);
//     goto err;
//   }

//   memset(list->plist, '\0', sizeof(struct port *) * nlen);
//   list->size = nlen;

//   return list;

// err:
//   XPERR_RT("failed to create port list.", list);
// }

// void free_layer_list(struct layer_list *list) {
//   if (IS_NULL(list))
//     return;

//   if (!IS_NULL(list->plist) && list->size > 0)
//     for (xulong i = 0; i < list->size; i++)
//       free_layer(*(list->plist + i));

//   free(list);
// }

// struct port *enum_device_maker(layer_handler handler, object *obj) {
//   API_LAYER_MAKER(la, size, enum_dev, (TRUE, NULL, &_size), handler,
//                   SKF_EnumDev);
//   return handler(_la, _enum_dev, obj) ? _la : (struct port *)NULL;
// }

// int enum_device_handler(struct port *la, func enum_dev, object *obj) {
//   API_LAYER_HANDLER(la, enum_dev, (TRUE, la->name, &la->size), SKF_EnumDev,
//   0); return 1;
// }

// struct port *get_raw_layer(layer_maker maker, layer_handler handler,
//                             object *obj) {
//   assert(NOT_NULL(maker) && NOT_NULL(handler));
//   return maker(handler, obj);
// }

// struct port *enum_app_maker(layer_handler handler, object *obj) {
//   device *dev = (device *)obj;
//   if (IS_NULL(dev) || IS_NULL(*dev))
//     return (struct port *)NULL;

//   API_LAYER_MAKER(la, size, enum_app, (*dev, NULL, &_size), handler,
//                   SKF_EnumApplication);
//   return handler(_la, _enum_app, obj) ? _la : (struct port *)NULL;
// }

// int enum_app_handler(struct port *la, func enum_app, object *obj) {
//   API_LAYER_HANDLER(la, enum_app, (*((device *)obj), la->name, &la->size),
//                     SKF_EnumApplication, 0);
//   return 1;
// }

// struct port *enum_container_maker(layer_handler handler, object *obj) {
//   application *app = (application *)obj;
//   if (IS_NULL(app) || IS_NULL(*app))
//     return (struct port *)NULL;

//   API_LAYER_MAKER(la, size, enum_container, (*app, NULL, &_size), handler,
//                   SKF_EnumContainer);
//   return handler(_la, _enum_container, obj) ? _la : (struct port *)NULL;
// }
// int enum_container_handler(struct port *la, func enum_container, object
// *obj) {
//   API_LAYER_HANDLER(la, enum_container,
//                     (*((application *)obj), la->name, &la->size),
//                     SKF_EnumContainer, 0);
//   return 1;
// }

// struct layer_list *get_layer_list(layer_maker maker, layer_handler handler,
//                                   object *obj) {
//   struct port *raw_la = NULL;
//   struct layer_list *la_list = NULL;
//   xulong *indices = NULL;
//   xulong idx_cnt = 0;
//   int flag = 0;

//   assert(NOT_NULL(maker) && NOT_NULL(handler));

//   if (IS_NULL(raw_la = get_raw_layer(maker, handler, obj)) ||
//       IS_NULL(indices = (int *)malloc(sizeof(int) * raw_la->size)))
//     goto err;

//   memset(indices, -1, sizeof(int) * raw_la->size);

//   for (xulong i = 0, j = 0; i < raw_la->size; i++) {
//     if (*(raw_la->name + i) != '\0') {
//       if (flag)
//         flag = 0;

//       continue;
//     }

//     if (flag) {
//       idx_cnt = j;
//       break;
//     }

//     flag = 1;

//     indices[j++] = i;
//   }

//   if (IS_NULL(la_list = init_layer_list(idx_cnt))) {
//     free_layer_list(la_list);
//     goto err;
//   }

//   struct port *tmp_la = NULL;
//   xulong tmp_size = 0;
//   xulong begin_idx = 0;

//   for (xulong i = 0; i < idx_cnt; i++) {
//     tmp_size = *(indices + i) - begin_idx + 1;

//     if (IS_NULL(tmp_la = init_layer(tmp_size)))
//       goto err;

//     memcpy(tmp_la->name, raw_la->name + begin_idx, tmp_size);
//     *(la_list->plist + i) = tmp_la;

//     if ((begin_idx += tmp_size) > raw_la->size)
//       break;
//   }

//   free(indices);

//   return la_list;

// err:
//   free(indices);

//   XPERR_RT("failed to decode list.", la_list);
// }

// struct layer_list *get_device_list() {
//   RETURN_LAYER_LIST(enum_device_maker, enum_device_handler, NULL);
// }

// struct layer_list *get_app_list(struct outlet *out) {
//   RETURN_LAYER_LIST(enum_app_maker, enum_app_handler, out->dev);
// }

// struct layer_list *get_container_list(struct outlet *out) {
//   RETURN_LAYER_LIST(enum_container_maker, enum_container_handler,
//   out->app);
// }

// int connect_device(const xchar *dev_name, struct outlet *out) {

//   assert(NOT_NULL(dev_name) && NOT_NULL(out));

//   API_EXTRACTOR(conn_dev, SKF_ConnectDev, 0);

//   if (IS_NULL(out->dev = (device *)malloc(sizeof(device))))
//     goto err;

//   memset(out->dev, '\0', sizeof(device));

//   if (_conn_dev(dev_name, out->dev) != SAR_OK) {
//     disconnect_device(out->dev);
//     out->dev = NULL;
//     goto err;
//   }

//   return 1;

// err:
//   XPERR_RT("failed to connect device.", 0);
// }

// void disconnect_device(struct outlet *out) {
//   F_SKF_DisConnectDev disconn_dev = NULL;

//   if (IS_NULL(out) || IS_NULL(out->dev))
//     return;

//   if (NOT_NULL(disconn_dev = API_EXTRACT(SKF_DisConnectDev)) &&
//       disconn_dev(*(out->dev)) != SAR_OK)
//     XPERR("failed to disconnect device.");

//   free(out->dev);
// }

// int open_application(const xchar *app_name, struct outlet *out) {
//   assert(NOT_NULL(out) && NOT_NULL(app_name));

//   API_EXTRACTOR(open_app, SKF_OpenApplication, out->app);

//   if (IS_NULL(out->dev) ||
//       IS_NULL(out->app = (application *)malloc(sizeof(application))))
//     goto err;

//   memset(out->app, '\0', sizeof(application));

//   if (_open_app(*(out->dev), app_name, out->app) != SAR_OK) {
//     close_application(out);
//     out->app = NULL;
//     goto err;
//   }

//   return 1;

// err:
//   XPERR_RT("failed to open application.", 0);
// }

// void close_application(struct outlet *out) {
//   F_SKF_CloseApplication close_app = NULL;

//   if (IS_NULL(out) || IS_NULL(out->app))
//     return;

//   if (NOT_NULL(close_app = API_EXTRACT(SKF_CloseApplication)) &&
//       close_app(*(out->app)) != SAR_OK)
//     XPERR("failed to close application.");

//   free(out->app);
// }

// int open_container(const xchar *container_name, struct outlet *out) {
//   assert(NOT_NULL(container_name) && NOT_NULL(out));

//   API_EXTRACTOR(open_conta, SKF_OpenContainer, out->conta);

//   if (IS_NULL(out->app) ||
//       IS_NULL(out->conta = (container *)malloc(sizeof(container))))
//     goto err;

//   memset(out->conta, '\0', sizeof(container));

//   if (_open_conta(*(out->app), container_name, out->conta) != SAR_OK) {
//     close_container(out);
//     out->conta = NULL;
//     goto err;
//   }

//   return 1;

// err:
//   XPERR_RT("failed to open container.", 0);
// }

// void close_container(struct outlet *out) {
//   F_SKF_CloseContainer close_conta = NULL;

//   if (IS_NULL(out) || IS_NULL(out->conta))
//     return;

//   if (NOT_NULL(close_conta = API_EXTRACT(SKF_CloseContainer)) &&
//       close_conta(*(out->conta)) != SAR_OK)
//     XPERR("failed to close container.");

//   free(out->conta);
// }

// int user_permission_auth(struct outlet *out) {
//   F_SKF_VerifyPIN verify_PIN = NULL;
//   xulong retry_cnt = 0;

//   assert(NOT_NULL(out));

//   if (IS_NULL(out->app) || IS_NULL(verify_PIN =
//   API_EXTRACT(SKF_VerifyPIN)))
//     goto err;

//   if (verify_PIN(*(out->app), USER_TYPE, K_PIN_CODE, &retry_cnt) != SAR_OK)
//   {
//     fprintf(stderr, "WARNING: PIN retry counts: %lu\n", retry_cnt);
//     goto err;
//   }

//   return 1;

// err:
//   XPERR_RT("failed to verify PIN", 0);
// }

// struct outlet *init_outlet() {
//   struct outlet *out = NULL;
//   struct layer_list *dev_list = NULL;
//   struct layer_list *app_list = NULL;
//   struct layer_list *container_list = NULL;

//   if (IS_NULL(out = (struct outlet *)malloc(sizeof(struct outlet))))
//     XPERR_RT("failed to init outlet.", out);

//   memset(out, '\0', sizeof(struct outlet));

//   if (IS_NULL(dev_list = get_device_list()) ||
//       !connect_device((*dev_list->plist)->name, out) ||
//       IS_NULL(app_list = get_app_list(out)) ||
//       !open_application((*app_list->plist)->name, out) ||
//       !user_permission_auth(out) ||
//       IS_NULL(container_list = get_container_list(out)) ||
//       !open_container((*container_list->plist)->name, out)) {
//     free_outlet(out);
//     out = NULL;
//     XPERR("failed to init outlet.");
//   }

//   free_layer_list(container_list);
//   free_layer_list(app_list);
//   free_layer_list(dev_list);

//   return out;
// }

// void free_outlet(struct outlet *out) {
//   if (IS_NULL(out))
//     return;

//   close_container(out);
//   close_application(out);
//   disconnect_device(out);
//   free(out);
//   out = NULL;
// }

// int fx_outlet_set_port(fx_outlet_t *outlet, fx_port_type type,
//                        fx_bytes_t port) {
//   int ret = fx_port_type_check(type);
//   if (ret) {
//     switch (type) {
//     case FX_DEV_PORT:
//       ret = fx_outlet_load_dev(outlet, port);
//       break;

//     case FX_APP_PORT:
//       ret = fx_outlet_load_app(outlet, port);
//       break;

//     case FX_CONTA_PORT:
//       ret = fx_outlet_load_conta(outlet, port);
//       break;

//     default:
//       ret = 0;
//       break;
//     }
//   }

//   return ret;
// }

// FX_PORT_OP_DECLARE(dev_load) {
//   int ret = 0;

//   if (outlet->dev) {
//     ret = port->close(outlet, port);
//     if (!ret)
//       goto end;
//   }

//   ret = SKF_ConnectDev(port->name.ptr, outlet->dev);
//   if (ret == SAR_OK) {
//     outlet->dev_id = fx_bytes_clone(port->name);
//     ret = 1;
//   }

// end:
//   return ret;
// }

// FX_PORT_OP_DECLARE(dev_unload) {
//   int ret = 1;

//   fx_bytes_free(&outlet->dev_id);
//   if (outlet->dev) {
//     ret = SKF_DisConnectDev(*outlet->dev);
//     if (ret == SAR_OK) {
//       outlet->dev = NULL;
//       ret = 1;
//     }
//   }

//   return ret;
// }

// #pragma mark - fx_outlet_app impl.
// FX_PORT_OP_DECLARE(app_add) {
//   int ret = 0;

//   if (!outlet->dev)
//     goto end;

//   if (outlet->app) {
//     ret = 1;
//     goto end;
//   }

//   ret = SKF_CreateApplication(
//       *outlet->dev, port->name.ptr, outlet->pin, FX_PIN_RETRY_TIMES,
//       outlet->pin, FX_PIN_RETRY_TIMES, SECURE_USER_ACCOUNT, outlet->app);
//   if (ret == SAR_OK) {
//     outlet->app_id = fx_bytes_clone(port->name);
//     ret = 1;
//   }

// end:
//   return ret;
// }

#pragma mark - fx_outlet_t
struct fx_outlet {
  const char *pin;
  const char *authkey;
  char *auth;

  fx_port_t *pdev, *papp, *pconta;
};

static char *fx_outlet_gen_auth(fx_outlet_t *outlet) {}

fx_outlet_t *fx_outlet_new(const char *authkey, const char *pin) {
  fx_outlet_t *outlet = NULL;

  if (!authkey || !pin)
    goto end;

  outlet = (fx_outlet_t *)calloc(1, sizeof(fx_outlet_t));
  if (!outlet)
    goto end;

  outlet->authkey = strdup(authkey);
  outlet->pin = strdup(pin);
  if (!outlet->authkey || !outlet->pin) {
    fx_outlet_free(outlet);
    outlet = NULL;
    goto end;
  }

  // outlet->dev_id = fx_bytes_empty();
  // outlet->app_id = fx_bytes_empty();
  // outlet->conta_id = fx_bytes_empty();

end:
  return outlet;
}

void fx_outlet_free(fx_outlet_t *outlet) {
  if (outlet) {
    if (outlet->authkey) {
      free((void *)outlet->authkey);
      outlet->authkey = NULL;
    }

    if (outlet->pin) {
      free((void *)outlet->pin);
      outlet->pin = NULL;
    }

    if (outlet->auth) {
      free(outlet->auth);
      outlet->auth = NULL;
    }
  }
}

const char *fx_outlet_get_pin(fx_outlet_t *outlet) { return outlet->pin; }

int fx_outlet_validate(fx_outlet_t *outlet) {}
