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
    f = fx_field_new(t, l, calloc(l, sizeof(uint8_t)));
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

#pragma mark - fx_chunk_t
struct fx_chunk {
  size_t n, flat_len;
  fx_bytes_t nlist;
  fx_bytes_t *blist;
};

static inline fx_chunk_t *fx_chunk_new(size_t n) {
  fx_chunk_t *chunk = NULL;
  if (n && (chunk = (fx_chunk_t *)calloc(1, sizeof(fx_chunk_t)))) {
    chunk->n = n;
    chunk->nlist = fx_bytes_calloc(n * sizeof(size_t));
    chunk->blist = (fx_bytes_t *)calloc(n, sizeof(fx_bytes_t));
    if (!chunk->blist || !fx_bytes_check(&chunk->nlist)) {
      fx_chunk_free(chunk);
      chunk = NULL;
    }
  }
  return chunk;
}

static inline fx_chunk_t *fx_chunk_pack_ex(size_t n, void *list,
                                           fx_bytes_t (*iter)(void *, size_t)) {
  size_t mlen = 0;
  fx_chunk_t *chunk = fx_chunk_new(n);
  if (chunk) {
    for (size_t i = 0; i < n; ++i)
      mlen += *(((size_t *)chunk->nlist.ptr) + i) =
          (*(chunk->blist + i) = fx_bytes_clone(iter(list, i))).len;

    if (mlen) {
      chunk->flat_len = mlen;
    } else {
      fx_chunk_free(chunk);
      chunk = NULL;
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
    if (chunk->blist) {
      for (size_t i = 0; i < chunk->n; ++i)
        fx_bytes_free(chunk->blist + i);

      free(chunk->blist);
    }
    fx_bytes_free(&chunk->nlist);
    free(chunk);
  }
}