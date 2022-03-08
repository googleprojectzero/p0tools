# WebKit Fuzzing

This project includes directions and a patch ([webkit.patch](https://github.com/googleprojectzero/p0tools/blob/master/WebKitFuzz/webkit.patch)) to make fuzzing WebKit easier. We use the WebKitGTK+ implementation, running on Linux as the fuzzing target. This patch and instructions will build WebKitGTK+ with ASAN and make some changes that make fuzzing easier.

The patch file was made with [WebKitGTK+ version 2.34.6](https://webkitgtk.org/releases/webkitgtk-2.34.6.tar.xz) and/or the WebKit Github repo as of commit [690b38f1f792a1d9c72f3fcb6f8add83090d459a](https://github.com/WebKit/WebKit/tree/690b38f1f792a1d9c72f3fcb6f8add83090d459a). It might not work as is on other versions.

List of changes:

 - Fixes to be able to build WebKitGTK+ with ASan.

 - Changed window.alert() implementation to immediately call the garbage collector instead of displaying a message window.

 - As soon as any web process crashes, exit the main process with the same exit code.

 - Created a custom target binary (webkitfuzz).

 - Enable javascript console logging to terminal.


## Building webkitfuzz & WebKit

There are two options for building WebKitGTK+: WebKitGTK+ stable release tarball
or the WebKit git repo. These instructions support both options.

1. Get the code by either downloading and extracting the [WebKitGTK+ tarball  version 2.34.6](https://webkitgtk.org/releases/webkitgtk-2.34.6.tar.xz) or cloning the WebKit git repo as of commit [690b38f1f792a1d9c72f3fcb6f8add83090d459a](https://github.com/WebKit/WebKit/tree/690b38f1f792a1d9c72f3fcb6f8add83090d459a).

2. Apply the changes in [webkit.patch](https://github.com/googleprojectzero/p0tools/blob/master/WebKitFuzz/webkit.patch) by running one of the following commands from the root of your WebKit tree: 

   `patch -p1 < webkit.patch` (tarball)  or `git apply webkit.patch` (git repo)

3. Build WebKit by running the  build script ([`build_webkitfuzz.sh`](https://github.com/googleprojectzero/p0tools/blob/master/WebKitFuzz/build_webkitfuzz.sh)) from the root of the WebKit
tree (`webkitgtk-2.34.6/` or `WebKit/`). This script will place the built files
into the `build/` directory.

    During the `cmake` stage, WebKit will likely yell at you to install
    requisite libraries. Many dependencies are turned off with the `ENABLE` and
    `USE` flags, but many are still required.

   The build process works with either
   `make` or `ninja`. Our scripts use `make`, but replacing with `ninja` should
   work as well.

   *NOTE:* The official WebKit build instructions recommend building with
   `Tools/Scripts/build-webkit`. In our experience this is a less reliable
   process for the purposes of building a separate target binary that will call and start the
   WebKit processes.

4. Run the fuzzer binary from the build directory (`build/`) with the following command. The sample can either be a path to a file or a URL beginning with `http` or `https`.
```
   ASAN_OPTIONS=detect_leaks=0,exitcode=42,log_path=asan_logs/crash ASAN_SYMBOLIZER_PATH=</path/to/llvm-symbolizer> LD_LIBRARY_PATH=lib/ ./bin/webkitfuzz </path/to/sample> <timeout in sec>
```

## Other Tips and Tricks

If your build is succeeding, but you're not seeing the expected output during a
run, check that your webkitfuzz is actually using WebKit executables and
libraries that you build rather than the default ones on your machine:

1. Make sure you include the environment variable: `LD_LIBRATY_PATH=lib/`
2. When webkitfuzz is running in another terminal run `ps -aux | grep WebKit` to
   check that the `WebKitWebProcess` and `WebKitNetworkProcess` that are running
   are from your build directory.
3. Check that webkitfuzz is using the webkit and javascriptcore libraries from
   your build by running: `ldd bin/webkitfuzz` and checking what
   `libwebkit2gtk-4.0.so.37` and `libjavascriptcoregtk-4.0.so.18` point to.


#### Other cmake flags

Depending on what your fuzzing set-up and what you're trying to fuzz the
following additional cmake flags can reduce build time and dependencies:
```
-DENABLE_VIDEO=OFF
-DENABLE_WEB_AUDIO=OFF
-DENABLE_GAMEPAD=OFF
-DENABLE_MEDIA_STREAM=OFF
```

#### USE_SYSTEM_MALLOC flag

Our script currently sets the `-DUSE_SYSTEM_MALLOC=ON`. When
`-DUSE_SYSTEM_MALLOC=OFF`, WebKit's `bmalloc` is used in of the system's `malloc`. `bmalloc` adds exploit mitigations that WebKit has implemented such as IsoHeap and GigaCage. Using the system's `malloc` may lead to better ASAN coverage. Change this flag based on your fuzzing needs.

#### Symbolizing crashes

If the symobilizing doesn't seem to be working, make sure that you've set
ASAN_SYMBOLIZER_PATH to the version of the symbolizer that matches which clang
version you're using to build WebKit. Among the first console prints when you
run the build script, you'll see which compiler is running. For example:
```
-- The C compiler identification is Clang 13.0.1
-- The CXX compiler identification is Clang 13.0.1
```
In this case you'd want to make sure you link to your llvm-symoblizer-13 binary
since you're using clang-13.