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

#include <cmocka_addon.h>

#include <test_outlet.h>
#include <test_utils.h>

int main(int argc, char const *argv[]) {
  const struct CMUnitTest tests[] = {
      unit_test(test_ubytes),
      unit_test(test_fx_outlet),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
