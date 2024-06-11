# This file is part of project [fx-keygen].
#
# Copyright (c) 2024-Present VARRIX All Rights Reserved.
#
# Author: VARRTIX
# Created Date: 2024/05/27
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

cmake_minimum_required(VERSION 3.20 FATAL_ERROR)

project(fx_keygen LANGUAGES C)

set(SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
set(INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(INTERNAL_INCLUDE_DIR ${SOURCE_DIR}/include)
set(LIB_DIR ${PROJECT_SOURCE_DIR}/lib)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(BUILD_TYPE debug)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
else()
    set(BUILD_TYPE release)
endif()
set(GM3000_LIB_NAME gm3000.1.0)
set(GM3000_LIB_DIR ${LIB_DIR}/gm3000/${CMAKE_SYSTEM_PROCESSOR}/${BUILD_TYPE})

# Library: libfx_keygen
file(GLOB SOURCE_LIST ${SOURCE_DIR}/*.c)
add_library(${PROJECT_NAME} SHARED ${SOURCE_LIST})
target_include_directories(${PROJECT_NAME} PUBLIC 
    ${INCLUDE_DIR} 
    ${INTERNAL_INCLUDE_DIR}
)
target_link_directories(${PROJECT_NAME} PUBLIC ${GM3000_LIB_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC ${GM3000_LIB_NAME})

# Unit Testing
set(TEST_NAME test_${PROJECT_NAME})
set(TEST_DIR ${PROJECT_SOURCE_DIR}/test)
set(TEST_INCLUDE_DIR ${TEST_DIR}/include)
set(TEST_SOURCE_DIR ${TEST_DIR}/src)

enable_testing()
find_package(CMocka REQUIRED)
if (CMocka_FOUND)
    file(GLOB TEST_SOURCE_LIST ${TEST_SOURCE_DIR}/*.c)
    add_executable(${TEST_NAME} 
        ${TEST_DIR}/main.c
        ${TEST_SOURCE_LIST}
    )
    target_include_directories(${TEST_NAME} PUBLIC 
        ${INCLUDE_DIR}
        ${INTERNAL_INCLUDE_DIR}
        ${TEST_INCLUDE_DIR}
    ) 
    target_link_directories(${TEST_NAME} PUBLIC ${GM3000_LIB_DIR})
    target_link_libraries(${TEST_NAME} 
        ${PROJECT_NAME} 
        ${GM3000_LIB_NAME}
        cmocka 
    ) 
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endif()