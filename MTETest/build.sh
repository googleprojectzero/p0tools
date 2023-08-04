#! /bin/sh

# Copyright 2023 Google LLC
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

export ADB_PATH=adb
export CLANG_PATH=/ssd/llvm/build/bin/clang
export CFLAGS='--target=aarch64-linux -march=armv8a+memtag -std=gnu99 -O2 -Wall -Wextra -I./'
export LDFLAGS='-lpthread -lm -fuse-ld=lld -static'

# Build ./lib
$CLANG_PATH $CFLAGS -c ./lib/histogram.c ./lib/mte.c ./lib/perf_counters.c ./lib/scheduler.c ./lib/timer.c
export SHARED_OBJECTS='./histogram.o ./mte.o ./perf_counters.o ./scheduler.o ./timer.o'

# Build duktape library
wget https://duktape.org/duktape-2.7.0.tar.xz
tar xvf duktape-2.7.0.tar.xz
$CLANG_PATH $CFLAGS -c ./duktape-2.7.0/src/duktape.c
export DUKTAPE_INCLUDE_PATH='./duktape-2.7.0/src'
export DUKTAPE_OBJECTS='./duktape.o'

# Build test binaries
$CLANG_PATH $CFLAGS $LDFLAGS ./software_issue_1.c $SHARED_OBJECTS -o software_issue_1
$CLANG_PATH $CFLAGS $LDFLAGS ./software_issue_2.c $SHARED_OBJECTS -o software_issue_2
$CLANG_PATH $CFLAGS $LDFLAGS ./speculation_window.c $SHARED_OBJECTS -o speculation_window
$CLANG_PATH $CFLAGS $LDFLAGS ./async_signal_handler_bypass.c $SHARED_OBJECTS $DUKTAPE_OBJECTS -I$DUKTAPE_INCLUDE_PATH -o async_signal_handler_bypass
$CLANG_PATH $CFLAGS $LDFLAGS ./async_thread_bypass.c $SHARED_OBJECTS $DUKTAPE_OBJECTS -I$DUKTAPE_INCLUDE_PATH -o async_thread_bypass

# Push all needed files to device
$ADB_PATH push ./software_issue_1 /data/local/tmp/software_issue_1
$ADB_PATH push ./software_issue_2 /data/local/tmp/software_issue_2
$ADB_PATH push ./speculation_window /data/local/tmp/speculation_window
$ADB_PATH push ./async_signal_handler_bypass /data/local/tmp/async_signal_handler_bypass
$ADB_PATH push ./async_signal_handler_bypass.js /data/local/tmp/async_signal_handler_bypass.js
$ADB_PATH push ./async_thread_bypass /data/local/tmp/async_thread_bypass
$ADB_PATH push ./async_thread_bypass.js /data/local/tmp/async_thread_bypass.js