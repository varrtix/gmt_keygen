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

#include "cmocka_addon.h"

#include "fx/outlet.h"

void test_fx_port_list(void **state) {
  size_t len = 0;
  char **list;
  fx_port_list_t *dev_plist = fx_port_list_new(FX_DEV_PORT, NULL);
  const char *peek_name;
  assert_ptr_not_equal(dev_plist, NULL);

  assert_int_equal(fx_port_list_export2char(dev_plist, NULL, &len), 1);
  assert_int_equal(len, fx_port_list_size(dev_plist));
  assert_ptr_not_equal(list = (char **)test_calloc(len, sizeof(char *)), NULL);
  assert_int_equal(fx_port_list_export2char(dev_plist, list, &len), 1);

  for (size_t i = 0; i < len; ++i) {
    print_message("[dev port %d] %s\n", i, *(list + i));
    if (*(list + i))
      free(*(list + i));
  }

  assert_ptr_not_equal(
      peek_name = fx_port_list_peek_name2char(dev_plist, 0, NULL), NULL);
  print_message("[dev port 0] peek: %s\n", peek_name);

  test_free(list);
  fx_port_list_free(dev_plist);
}

void test_fx_port(void **state) {}

void test_fx_outlet(void **state) {
  const char *pin = "12345678";
  // fx_outlet_t *outlet = fx_outlet_new(pin);
  // assert_ptr_not_equal(outlet, NULL);
  // assert_string_equal(fx_outlet_get_pin(outlet), pin);
}