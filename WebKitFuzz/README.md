### WebKit Fuzzing

webkit.patch is a patch file that makes it easier to build WebKitGTK+ with ASan and fuzz it.

The patch file was made with WebKitGTK+ version 2.20.2 (https://webkitgtk.org/releases/webkitgtk-2.20.2.tar.xz) and might not work as is on other versions.

List of changes:

 - Fixes to be able to build WebKitGTK+ with ASan

 - Changed window.alert() implementation to immediately call the garbage collector instead of displaying a message window.

 - As soon as any web process crashes, exit the main process with the same exit code.

 - Created a custom target binary (webkitfuzz)

After applying the patch, you can build using the following commands:

```
export CC=/usr/bin/clang
export CXX=/usr/bin/clang++
export CFLAGS="-fsanitize=address"
export CXXFLAGS="-fsanitize=address"
export LDFLAGS="-fsanitize=address"
export ASAN_OPTIONS="detect_leaks=0"

mkdir build
cd build

cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=. -DCMAKE_SKIP_RPATH=ON -DPORT=GTK -DLIB_INSTALL_DIR=./lib -DUSE_LIBHYPHEN=OFF -DENABLE_MINIBROWSER=ON -DUSE_SYSTEM_MALLOC=ON -DENABLE_GEOLOCATION=OFF -DENABLE_GTKDOC=OFF -DENABLE_INTROSPECTION=OFF -DENABLE_OPENGL=OFF -DENABLE_ACCELERATED_2D_CANVAS=OFF -DENABLE_CREDENTIAL_STORAGE=OFF -DENABLE_GAMEPAD_DEPRECATED=OFF -DENABLE_MEDIA_STREAM=OFF -DENABLE_WEB_RTC=OFF -DENABLE_PLUGIN_PROCESS_GTK2=OFF -DENABLE_SPELLCHECK=OFF -DENABLE_VIDEO=OFF -DENABLE_WEB_AUDIO=OFF -DUSE_LIBNOTIFY=OFF -DENABLE_SUBTLE_CRYPTO=OFF -DUSE_WOFF2=OFF -Wno-dev ..

make -j 4

mkdir -p libexec/webkit2gtk-4.0
cp bin/WebKit*Process libexec/webkit2gtk-4.0/

```

And install dependencies when it complains. Note that some of the dependencies were already removed via `-DENABLE_...=OFF` flags. These flags are mosly not necessary, but you will need to install additional dependencies if you remove them.

After it builds, you can run the fuzzer binary as:

`ASAN_OPTIONS=detect_leaks=0,exitcode=42 ASAN_SYMBOLIZER_PATH=/path/to/llvm-symbolizer LD_LIBRARY_PATH=./lib ./bin/webkitfuzz /path/to/sample <timeout>`

Note that exit code 42 will indicate an ASan crash.

