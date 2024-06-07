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

#include "fx/utils.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#pragma mark - fx_bytes_t
fx_bytes_t fx_bytes_new(uint8_t *ptr, size_t len) {
  return (fx_bytes_t){
      .ptr = ptr,
      .len = len,
  };
}

fx_bytes_t fx_bytes_calloc(size_t len) {
  fx_bytes_t ubytes = fx_bytes_empty();
  if (len) {
    ubytes = fx_bytes_new(calloc(len, sizeof(uint8_t)), len);
    ubytes.len = ubytes.ptr ? len : 0;
  }
  return ubytes;
}

fx_bytes_t fx_bytes_clone(fx_bytes_t ubytes) {
  fx_bytes_t new_ubytes = fx_bytes_calloc(ubytes.len);
  if (new_ubytes.ptr)
    memcpy(new_ubytes.ptr, ubytes.ptr, ubytes.len);
  return new_ubytes;
}

void fx_bytes_free(fx_bytes_t *ubytes) {
  if (ubytes->ptr) {
    free(ubytes->ptr);
    ubytes->ptr = NULL;
    ubytes->len = 0;
  }
}

#pragma mark - fx_field_t
fx_field_t fx_field_new(uint16_t t, uint16_t l, uint8_t *v) {
  return (fx_field_t){.t = t, .l = l, .v = v};
}

fx_field_t fx_field_calloc(uint16_t t, uint16_t l) {
  fx_field_t f = fx_field_empty(t);
  if (l) {
    f.l = l;
    f = fx_field_new(t, l, calloc(sizeof(uint8_t) * l, 1));
    f.l = f.v ? l : 0;
  }
  return f;
}

fx_field_t fx_field_clone(fx_field_t f) {
  fx_field_t nf = fx_field_calloc(f.t, f.l);
  if (nf.v)
    memcpy(nf.v, f.v, f.l);
  return nf;
}

void fx_field_free(fx_field_t *f) {
  if (f->v) {
    free(f->v);
    f->v = NULL;
    f->t = f->l = 0;
  }
}

fx_bytes_t fx_field2bytes_flat(fx_field_t f) {
  size_t l = fx_field_capacity(&f), offset = sizeof(uint16_t);
  fx_bytes_t ff = fx_bytes_empty();
  uint8_t *ptr;
  if (l && fx_field_check(&f)) {
    ff = fx_bytes_calloc(l);
    if (fx_bytes_check(&ff)) {
      ptr = ff.ptr;
      memcpy(ptr, &f.t, offset);
      ptr += offset;
      memcpy(ptr, &f.l, offset);
      ptr += offset;
      memcpy(ptr, f.v, sizeof(uint8_t) * f.l);
    }
  }
  return ff;
}

fx_field_t fx_bytes2field_compact(fx_bytes_t b) {
  fx_field_t f = fx_field_empty(0), *ff;
  if (fx_bytes_check(&b)) {
    ff = (fx_field_t *)b.ptr;
    if (b.len == fx_field_capacity(ff)) {
      f = fx_field_calloc(ff->t, ff->l);
      if (fx_field_check(&f))
        memcpy(f.v, b.ptr + FX_FIELD_PREFIX_SIZE, f.l * sizeof(uint8_t));
    }
  }
  return f;
}

#pragma mark - fx_chunk_t
#define FX_CHUNK_FOR_EACH(chunk, idx, elem)                                    \
  fx_bytes_t *elem;                                                            \
  for (size_t idx = 0; idx < chunk->n; ++idx)                                  \
    if (elem = fx_chunk_get_element(chunk, idx))

struct fx_chunk {
  size_t n, flat_size;
  fx_bytes_t list;
};

static inline int fx_chunk_check(fx_chunk_t *chunk) {
  return chunk && chunk->n && fx_bytes_check(&chunk->list);
}

static inline fx_bytes_t *fx_chunk_get_blist(fx_chunk_t *chunk) {
  return (fx_bytes_t *)chunk->list.ptr;
}

static inline fx_bytes_t *fx_chunk_get_element(fx_chunk_t *chunk, size_t idx) {
  return fx_chunk_get_blist(chunk) + idx;
}

static inline fx_chunk_t *fx_chunk_new(size_t n) {
  fx_chunk_t *chunk = NULL;
  if (n && (chunk = (fx_chunk_t *)calloc(1, sizeof(fx_chunk_t)))) {
    chunk->n = n;
    chunk->list = fx_bytes_calloc(n * sizeof(fx_bytes_t));
    if (!fx_bytes_check(&chunk->list)) {
      fx_chunk_free(chunk);
      chunk = NULL;
    }
  }
  return chunk;
}

static inline fx_chunk_t *fx_chunk_pack_ex(size_t n, void *list,
                                           fx_bytes_t (*iter)(void *, size_t)) {
  fx_chunk_t *chunk = NULL;
  if (list) {
    if (chunk = fx_chunk_new(n)) {
      FX_CHUNK_FOR_EACH(chunk, i, v) {
        chunk->flat_size += (*v = fx_bytes_clone(iter(list, i))).len;
      }

      if (!chunk->flat_size) {
        fx_chunk_free(chunk);
        chunk = NULL;
      }
    }
  }
  return chunk;
}

static inline fx_bytes_t fx_chunk_pack_iter(void *list, size_t idx) {
  return va_arg(*(va_list *)list, fx_bytes_t);
}

fx_chunk_t *fx_chunk_pack(size_t n, ...) {
  va_list list;
  fx_chunk_t *chunk;
  va_start(list, n);
  chunk = fx_chunk_pack_ex(n, &list, fx_chunk_pack_iter);
  va_end(list);
  return chunk;
}
static inline fx_bytes_t fx_chunk_pack_arr_iter(void *list, size_t idx) {
  return *((fx_bytes_t *)list + idx);
}

fx_chunk_t *fx_chunk_pack_arr(size_t n, const fx_bytes_t list[]) {
  return fx_chunk_pack_ex(n, (void *)list, fx_chunk_pack_arr_iter);
}

void fx_chunk_free(fx_chunk_t *chunk) {
  if (chunk) {
    if (fx_bytes_check(&chunk->list)) {
      FX_CHUNK_FOR_EACH(chunk, i, v) {
        fx_bytes_free(fx_chunk_get_element(chunk, i));
      }

      fx_bytes_free(&chunk->list);
    }
    free(chunk);
  }
}

size_t fx_chunk_get_size(fx_chunk_t *chunk) {
  return fx_chunk_check(chunk) ? chunk->n : 0;
}

size_t fx_chunk_get_flat_size(fx_chunk_t *chunk) {
  return fx_chunk_check(chunk) ? chunk->flat_size : 0;
}

fx_bytes_t fx_chunk_peek(fx_chunk_t *chunk, size_t idx) {
  return idx < fx_chunk_get_size(chunk) ? *fx_chunk_get_element(chunk, idx)
                                        : fx_bytes_empty();
}

fx_bytes_t fx_chunk_get(fx_chunk_t *chunk, size_t idx) {
  return fx_bytes_clone(fx_chunk_peek(chunk, idx));
}

fx_bytes_t fx_chunk_flat(fx_chunk_t *chunk) {
  size_t flat_size = fx_chunk_get_flat_size(chunk),
         size = fx_chunk_get_size(chunk),
         capacity =
             (flat_size && size ? (size + 1) * FX_FIELD_PREFIX_SIZE + flat_size
                                : 0);
  fx_bytes_t flat_chunk =
      capacity ? fx_bytes_calloc(capacity) : fx_bytes_empty();
  uint8_t *ptr;
  if (fx_bytes_check(&flat_chunk)) {
    flat_size = 0;
    size = sizeof(uint16_t);
    ptr = flat_chunk.ptr + size;
    *((uint16_t *)ptr) = flat_chunk.len - FX_FIELD_PREFIX_SIZE;
    ptr += size;
    FX_CHUNK_FOR_EACH(chunk, i, v) {
      ptr += size + flat_size;
      *((uint16_t *)ptr) = v->len;
      ptr += size;
      memcpy(ptr, v->ptr, v->len);
      flat_size = v->len;
    }
  }
  return flat_chunk;
}

fx_chunk_t *fx_chunk_compact(fx_bytes_t b) {
  size_t size, capacity, n = 0;
  fx_chunk_t *chunk = NULL;
  uint8_t *ptr;
  if (fx_bytes_check(&b)) {
    size = sizeof(uint16_t);
    capacity = *(uint16_t *)(ptr = b.ptr + size);
    if (capacity == b.len - FX_FIELD_PREFIX_SIZE) {
      ptr += size;
      for (size_t i = 0, j = 0; i < capacity; i += j) {
        ptr += size;
        j = *(uint16_t *)ptr;
        if (j) {
          ptr += j += size;
          j += size;
          n++;
        }
      }

      if (n) {
        chunk = fx_chunk_new(n);
        if (chunk) {
          n = capacity = 0;
          ptr = b.ptr + size * 2;
          FX_CHUNK_FOR_EACH(chunk, i, v) {
            ptr += size + n;
            n = *(uint16_t *)ptr;
            if (n) {
              *v = fx_bytes_calloc(n);
              if (!fx_bytes_check(v)) {
                fx_chunk_free(chunk);
                chunk = NULL;
                break;
              }
              memcpy(v->ptr, ptr += size, v->len);
              capacity += n;
            }
          }
          if (chunk)
            chunk->flat_size = capacity;
        }
      }
    }
  }
  return chunk;
}