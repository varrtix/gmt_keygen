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

#include <stdlib.h>
#include <string.h>

#pragma mark - vchunk_t
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
