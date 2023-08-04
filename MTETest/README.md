# MTE testing tools and examples.

This project includes a build script and code samples used to verify various
properties of the implementation of ARM MTE. See the blog post here for more
information:

https://googleprojectzero.blogspot.com/2023/08/mte-as-implemented-part-1.html

Note that most of these examples are written to demonstrate specific software
or hardware behaviour observed on a single test device configuration, so you
may encounter difficulties in reproducing the results in a different
environment, and will need to provide your own configuration for the core layout
of your test device, and likely also calibrate the timer and branch prediction
iterations (see config.py and config.h).