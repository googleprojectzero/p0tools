#!/bin/bash

echo "[*] Building webkitfuzz."

export CC=/usr/bin/clang
export CXX=/usr/bin/clang++

# -g flag for debugging symbols
# -w to skip printing warnings
# -Wfatal-error to immediately stop build with an error is detected
export CFLAGS="-fsanitize=address -g -w -Wfatal-error"
export CXXFLAGS="-fsanitize=address -g -w -Wfatal-error"
export LDFLAGS="-fsanitize=address -g"
export ASAN_OPTIONS="detect_leaks=0"

mkdir build
cd build

echo "[*] webkitfuzz: running cmake"

# Explanation of cmake flags:
# -DCMAKE_BULD_TYPE=Release -DPORT=GTK -- Build release build of WebKit GTK port
#
# -G "Unix Makefiles". Change to -G "Ninja" if you want to build with ninja
#
# -DCMAKE_INSTALL_PREFIX=. -DCMAKE_INSTALL_LIBEXECDIR=libexec/
# -DLIB_INSTALL_DIR=lib/ -DCMAKE_SKIP_RPATCH=ON - Required to have all the build
# files and libs end up in your build/ directory so webkitfuzz uses those files
# instead of the default on your machine
#
# -DENABLE_SANITIZERS=address - Build with ASAN
# -DENABLE_MINIBROWSER=ON - webkitfuzz uses minibrowser
#
# The rest turn off dependencies not needed for most fuzzing cases
cmake -DCMAKE_BUILD_TYPE=Release -DPORT=GTK -G "Unix Makefiles" \
  -DCMAKE_INSTALL_PREFIX=. -DCMAKE_SKIP_RPATH=ON -DLIB_INSTALL_DIR=./lib \
  -DCMAKE_INSTALL_LIBEXECDIR=./libexec \
  -DENABLE_SANITIZERS=address \
  -DENABLE_MINIBROWSER=ON \
  -DUSE_LIBSECRET=OFF \
  -DENABLE_GEOLOCATION=OFF \
  -DENABLE_GTKDOC=OFF \
  -DENABLE_MEDIA_STREAM=OFF \
  -DENABLE_WEB_RTC=OFF \
  -DUSE_SOUP2=ON \
  -DUSE_WPE_RENDERER=OFF \
  -DUSE_SYSTEMD=OFF \
  -DENABLE_INTROSPECTION=OFF \
  -DENABLE_SPELLCHECK=OFF \
  -DUSE_LIBNOTIFY=OFF \
  -DUSE_LIBHYPHEN=OFF \
  -DUSE_WOFF2=OFF \
  -DUSE_JPEGXL=OFF \
  -DENABLE_THUNDER=OFF \
  -DENABLE_JOURNALD_LOG=OFF \
  -DUSE_SYSTEM_MALLOC=ON \
  ..

# Calling make with <num cores>*2. Change based on your machine
echo "[*]: Calling make -j $((`nproc`*2))"
make -j$((`nproc`*2))

echo "[*] Finished make. Calling make install."
make install

echo "[*] Finished! Run webkitfuzz from build/ directory."
echo "[*] Command to run: ASAN_OPTIONS=detect_leaks=0,exitcode=42,log_path=asan_logs/ ASAN_SYMBOLIZER_PATH=</path/to/llvm-symbolizer> LD_LIBRARY_PATH=lib ./bin/webkitfuzz </path/to/sample> <timeout in sec>"
