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

#ifdef __cplusplus
}
#endif