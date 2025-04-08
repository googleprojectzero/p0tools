### Fuzzing Firefox with Jackalope

This directory contains a .patch file that demonstrates how to fuzz Firefox code with [Jackalope fuzzer](https://github.com/googleprojectzero/Jackalope). The patch adds Jackalope as a FuzzerDriver in addition to to the existing ones (libfuzzer, AFL).

The .patch also contains a target and the corresponding grammar for fuzzing Firefox's XSLT implementation using Jackalope's grammar mutator. This setup resulted in the discovery of CVE-2025-1932.

Note: The patch was created in February 2025 and might not apply cleanly to later versions.

An example mozconfig file suitable for fuzzing is included in this directory.

Once Jackalope and Firefox have been built, the XSLT fuzzer can be ran using the following example command line:

```
/path/to/Jackalope/build/fuzzer -grammar dom/xslt/fuzztest/ffgrammar.txt -instrumentation sancov -in empty -out out -t 5000 -delivery shmem -iterations 5000 -nthreads 6 -mute_child -target_env FUZZER=XSLTFuzzer -- objdir-ff-asan/dist/bin/firefox -m @@
```

