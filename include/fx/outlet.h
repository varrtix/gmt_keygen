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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include <fx/utils.h>

typedef void fx_obj_t;

#pragma mark - fx_port_t
typedef struct fx_port fx_port_t;
typedef enum {
  FX_DEFAULT_PORT = 0,
  FX_DEV_PORT,
  FX_APP_PORT,
  FX_CONTA_PORT,
  FX_MAX_PORT,
} fx_port_type;

fx_port_t *fx_port_new(fx_port_type type, fx_bytes_t name, int force,
                       fx_obj_t *obj);
void fx_port_free(fx_port_t *port);

int fx_port_open(fx_port_t *port);
int fx_port_close(fx_port_t *port);
fx_obj_t *fx_port_export(fx_port_t *port);

#pragma mark - fx_port_list_t
typedef struct fx_port_list fx_port_list_t;

fx_port_list_t *fx_port_list_new(fx_port_type type, fx_obj_t *obj);
void fx_port_list_free(fx_port_list_t *plist);

const char *fx_port_list_peek_name2char(fx_port_list_t *plist, size_t idx,
                                        size_t *nlen);
fx_bytes_t fx_port_list_get_name(fx_port_list_t *plist, size_t idx);
int fx_port_list_export2char(fx_port_list_t *plist, char **list, size_t *nlen);

#pragma mark - fx_outlet_t
typedef struct fx_outlet fx_outlet_t;

fx_outlet_t *fx_outlet_new(const char *authkey, const char *pin);
void fx_outlet_free(fx_outlet_t *outlet);

const char *fx_outlet_get_pin(fx_outlet_t *outlet);
int fx_outlet_validate(fx_outlet_t *outlet);
// int fx_outlet_set_port(fx_outlet_t *outlet, fx_port_type type, fx_bytes_t
// port);

// int skf_outlet_load_layers(fx_outlet_t *outlet, skf_layers_t *layers);

// struct layer_list {
// struct port **layers;
// xulong size;
// };

// struct outlet {
// device *dev;
// application *app;
// container *conta;
// };

// typedef int (*layer_handler)(struct port *, func, object *);
// typedef struct port *(*layer_maker)(layer_handler, object *);

// func extract(const char *func_name);

// struct port *init_layer(xulong nlen);
// void free_layer(struct port *la);

//  --mark--
// struct layer_list *init_layer_list(xulong nlen);
// void free_layer_list(struct layer_list *list);

// struct port *enum_device_maker(layer_handler handler, object *obj);
// int enum_device_handler(struct port *la, func enum_dev, object *obj);

// struct port *enum_app_maker(layer_handler handler, object *obj);
// int enum_app_handler(struct port *la, func enum_app, object *obj);

// struct port *enum_container_maker(layer_handler handler, object *obj);
// int enum_container_handler(struct port *la, func enum_container, object
// *obj);

// struct port *get_raw_layer(layer_maker maker, layer_handler handler,
//                             object *obj);

// struct layer_list *get_layer_list(layer_maker maker, layer_handler handler,
//                                   object *obj);

// struct layer_list *get_device_list();
// struct layer_list *get_app_list(struct outlet *out);
// struct layer_list *get_container_list(struct outlet *out);

// int connect_device(const xchar *dev_name, struct outlet *out);
// void disconnect_device(struct outlet *out);

// int open_application(const xchar *app_name, struct outlet *out);
// void close_application(struct outlet *out);

// int open_container(const xchar *container_name, struct outlet *out);
// void close_container(struct outlet *out);

// int user_permission_auth(struct outlet *out);

// struct outlet *init_outlet();
// void free_outlet(struct outlet *out);
// --end mark--

#ifdef __cplusplus
}
#endif