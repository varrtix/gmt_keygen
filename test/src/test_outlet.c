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

#include "test_outlet.h"

#include <stdlib.h>
#include <string.h>

#include "cmocka_addon.h"

#include "fx/keygen.h"
#include "fx/outlet.h"

const char *app_name = "fx-keygen-app";
const char *conta_name = "fx-keygen-conta";

fx_bytes_t test_fx_port_list(fx_port_list_t *plist, size_t idx) {
  char **list;
  size_t len = 0;
  fx_bytes_t port = fx_bytes_empty();
  assert_ptr_not_equal(plist, NULL);
  assert_int_equal(fx_port_list_export2char(plist, NULL, &len), 1);
  assert_int_equal(len, fx_port_list_size(plist));
  assert_ptr_not_equal(list = (char **)test_calloc(len, sizeof(char *)), NULL);
  assert_int_equal(fx_port_list_export2char(plist, list, &len), 1);

  for (size_t i = 0; i < len; ++i) {
    print_message("[dev port %d] %s\n", i, *(list + i));
    if (*(list + i))
      free(*(list + i));
  }
  test_free(list);

  return fx_port_list_get_name(plist, idx);
}

void test_fx_outlet(void **state) {
  fx_port_list_t *plist = fx_port_list_new(FX_DEV_PORT, NULL);
  fx_bytes_t port_name = fx_bytes_empty();
  fx_port_t *port;
  fx_outlet_t *outlet = fx_outlet_new("1234567812345678", "12345678");
  fx_ioctx_t *ioctx;
  fx_keychain_t *kc;
  fx_bytes_t auc_list[] = {
      fx_bytes_new("devid", 5),
      fx_bytes_new("provid", 6),
      fx_bytes_new("kmcid", 5),
  };

  assert_ptr_not_equal(outlet, NULL);

  port_name = test_fx_port_list(plist, 0);
  assert_int_equal(fx_bytes_check(&port_name), 1);
  print_message("[dev port 0] load: %s\n", port_name.ptr);
  assert_ptr_not_equal(
      port = fx_port_new(FX_DEV_PORT, port_name, FX_PF_OPEN, NULL, NULL), NULL);
  assert_int_equal(fx_port_busy(port), 1);
  assert_int_equal(fx_outlet_set_port(outlet, FX_DEV_PORT, port), 1);
  fx_bytes_free(&port_name);
  fx_port_list_free(plist);

  plist = fx_port_list_new(FX_APP_PORT, fx_port_export(port));
  port_name = plist ? test_fx_port_list(plist, 0)
                    : fx_bytes_new((uint8_t *)app_name, strlen(app_name));
  assert_int_equal(fx_bytes_check(&port_name), 1);
  print_message("[app port 0] load: %s\n", port_name.ptr);
  assert_ptr_not_equal(port = fx_port_new(FX_APP_PORT, port_name,
                                          FX_PF_OPEN | FX_PF_CREAT, outlet,
                                          fx_port_export(port)),
                       NULL);
  assert_int_equal(fx_port_busy(port), 1);
  assert_int_equal(fx_outlet_set_port(outlet, FX_APP_PORT, port), 1);
  fx_bytes_free(&port_name);
  fx_port_list_free(plist);

  plist = fx_port_list_new(FX_FILE_PORT, fx_port_export(port));
  port_name = fx_port_list_get_name(plist, 0);
  print_message("[file 0] name: %s\n", port_name.ptr);
  fx_bytes_free(&port_name);
  fx_port_list_free(plist);

  plist = fx_port_list_new(FX_CONTA_PORT, fx_port_export(port));
  port_name = plist ? test_fx_port_list(plist, 0)
                    : fx_bytes_new((uint8_t *)conta_name, strlen(conta_name));
  assert_int_equal(fx_bytes_check(&port_name), 1);
  print_message("[conta port 0] load: %s\n", port_name.ptr);
  assert_ptr_not_equal(port = fx_port_new(FX_CONTA_PORT, port_name,
                                          FX_PF_OPEN | FX_PF_CREAT, outlet,
                                          fx_port_export(port)),
                       NULL);
  assert_int_equal(fx_port_busy(port), 1);
  assert_int_equal(fx_outlet_set_port(outlet, FX_CONTA_PORT, port), 1);
  fx_bytes_free(&port_name);
  fx_port_list_free(plist);

  assert_ptr_not_equal(ioctx = fx_ioctx_new(), NULL);
  assert_int_equal(fx_ioctx_set(ioctx, FX_IOPT_OUTLET, outlet), 1);

  assert_ptr_not_equal(
      kc = fx_keychain_create(ioctx, FX_AUC_KEYCHAIN, auc_list), NULL);
  port_name = fx_keychain_encode(kc);
  assert_int_equal(fx_bytes_check(&port_name), 1);
  print_message("[encoded keychain][AUC][L: %d] %s\n", strlen(port_name.ptr),
                port_name.ptr);
  fx_keychain_destroy(kc);

  assert_ptr_not_equal(kc = fx_keychain_decode(port_name), NULL);
  fx_bytes_free(&port_name);
  port_name = fx_keychain_get_kte(kc);
  assert_int_equal(fx_bytes_check(&port_name), 1);
  assert_int_equal(port_name.len, 16);
  print_message("[AUC KTE][L: %d] %s\n", port_name.len, port_name.ptr);
  fx_bytes_free(&port_name);
  fx_keychain_destroy(kc);

  assert_ptr_not_equal(kc = fx_keychain_create2(
                           ioctx, FX_BM_KEYCHAIN, 4, fx_bytes_new("devid", 5),
                           fx_bytes_new("provid", 6), fx_bytes_new("kmcid", 5),
                           fx_bytes_new("aucid", 5)),
                       NULL);
  port_name = fx_keychain_encode(kc);
  assert_int_equal(fx_bytes_check(&port_name), 1);
  print_message("[encoded keychain][BM][L: %d] %s\n", strlen(port_name.ptr),
                port_name.ptr);
  fx_keychain_destroy(kc);

  assert_ptr_not_equal(kc = fx_keychain_decode(port_name), NULL);
  fx_bytes_free(&port_name);
  fx_keychain_destroy(kc);

  assert_ptr_not_equal(
      kc = fx_keychain_create(ioctx, FX_KMC_KEYCHAIN, auc_list), NULL);
  assert_int_equal(fx_ioctx_import_keychain(ioctx, kc), 1);
  fx_keychain_destroy(kc);
  assert_ptr_not_equal(kc = fx_ioctx_export_keychain(ioctx, FX_KMC_KEYCHAIN),
                       NULL);
  port_name = fx_keychain_encode(kc);
  assert_int_equal(fx_bytes_check(&port_name), 1);
  print_message("[encoded keychain][KMC][L: %d] %s\n", strlen(port_name.ptr),
                port_name.ptr);
  fx_bytes_free(&port_name);
  fx_keychain_destroy(kc);

  fx_ioctx_free(ioctx);
  fx_outlet_free(outlet);
}
