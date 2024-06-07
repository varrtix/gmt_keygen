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

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#pragma mark - fx_bytes_t
typedef struct {
  size_t len;
  uint8_t *ptr;
} fx_bytes_t;

fx_bytes_t fx_bytes_new(uint8_t *ptr, size_t len);
fx_bytes_t fx_bytes_calloc(size_t len);
fx_bytes_t fx_bytes_clone(fx_bytes_t bytes);
void fx_bytes_free(fx_bytes_t *bytes);

static inline fx_bytes_t fx_bytes_empty(void) { return fx_bytes_new(NULL, 0); }
static inline int fx_bytes_check(fx_bytes_t *bytes) {
  return bytes->ptr && bytes->len;
}

#pragma mark - fx_field_t
typedef struct {
  uint16_t t;
  uint16_t l;
  uint8_t *v;
} fx_field_t;

fx_field_t fx_field_new(uint16_t t, uint16_t l, uint8_t *v);
fx_field_t fx_field_calloc(uint16_t t, uint16_t l);
fx_field_t fx_field_clone(fx_field_t f);
void fx_field_free(fx_field_t *f);

static const size_t FX_FIELD_PREFIX_SIZE = sizeof(uint16_t) + sizeof(uint16_t);

static inline fx_field_t fx_field_empty(uint16_t t) {
  return fx_field_new(t, 0, NULL);
}
static inline int fx_field_check(fx_field_t *f) { return f->l && f->v; }
static inline size_t fx_field_capacity(fx_field_t *f) {
  return FX_FIELD_PREFIX_SIZE + f->l;
}
static inline fx_field_t fx_bytes2field(uint16_t t, fx_bytes_t b) {
  return fx_field_new(t, b.len, b.ptr);
}
static inline fx_field_t fx_bytes2field_clone(uint16_t t, fx_bytes_t b) {
  return fx_bytes2field(t, fx_bytes_clone(b));
}
static inline fx_bytes_t fx_field2bytes(fx_field_t f) {
  return fx_bytes_new(f.v, f.l);
}
static inline fx_bytes_t fx_field2bytes_clone(fx_field_t f) {
  return fx_field2bytes(fx_field_clone(f));
}

fx_bytes_t fx_field2bytes_flat(fx_field_t f);
fx_field_t fx_bytes2field_compact(fx_bytes_t b);

#pragma mark - fx_chunk_t
typedef struct fx_chunk fx_chunk_t;

fx_chunk_t *fx_chunk_pack(size_t n, ...);
fx_chunk_t *fx_chunk_pack_arr(size_t n, const fx_bytes_t list[]);
void fx_chunk_free(fx_chunk_t *chunk);

size_t fx_chunk_get_size(fx_chunk_t *chunk);
size_t fx_chunk_get_flat_size(fx_chunk_t *chunk);
fx_bytes_t fx_chunk_peek(fx_chunk_t *chunk, size_t idx);
fx_bytes_t fx_chunk_get(fx_chunk_t *chunk, size_t idx);

fx_bytes_t fx_chunk_flat(fx_chunk_t *chunk);

#ifdef __cplusplus
}
#endif