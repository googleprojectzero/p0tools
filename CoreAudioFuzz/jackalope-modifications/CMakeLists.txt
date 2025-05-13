# Copyright 2025 Google LLC
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION "3.1")
set (CMAKE_CXX_STANDARD 17)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/Jackalope)

if(APPLE)
  # If the active architecture is arm64 (Apple Silicon), define the same macros
  # Jackalope uses so <tinyinst.h> selects the correct code paths.
  if("${CMAKE_OSX_ARCHITECTURES}" MATCHES "arm64" OR
     CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "arm64")
    message(STATUS "Configuring CoreAudioFuzz for Apple Silicon (arm64)")
    add_definitions(-D__arm64__=1 -D__aarch64__=1 -DARM64=1)
  endif()
endif()

add_subdirectory(Jackalope)

add_executable(coreaudiofuzzer
  main.cpp
  function_hooks.cpp
  tinyinsthookinstrumentation.cpp
)

target_link_libraries(coreaudiofuzzer fuzzerlib)
