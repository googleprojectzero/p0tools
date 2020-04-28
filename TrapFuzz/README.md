# TrapFuzz

Hacky support for (basic-block) coverage guided fuzzing of closed source libraries for honggfuzz.

See https://googleprojectzero.blogspot.com/2020/04/fuzzing-imageio.html for some more information.

## Usage

1. Enumerate all basic blocks of the target library with the findPatchPoints.py IDAPython script

2. Apply trapfuzz.patch to [hoggfuzz](https://github.com/google/honggfuzz) and build honggfuzz

3. Implement a runner to call the API with fuzz input, see runner.m for an example

4. Compile the runner with honggfuzz's clang wrapper:

    $honggfuzz/hfuzz_cc/hfuzz-clang -o runner runner.m -framework Foundation -framework CoreGraphics -framework AppKit

5. Start fuzzing!

    $honggfuzz/honggfuzz --input input --output output --threads 12 --env TRAPFUZZ_FILE=trapfuzz.patches --env OS_ACTIVITY_MODE=disable --env DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib --rlimit_rss 4096 -- ./runner

