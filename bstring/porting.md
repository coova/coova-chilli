Better String Library Porting Guide
===================================

by Paul Hsieh

The bstring library is an attempt to provide improved string processing
functionality to the C language. At the heart of the bstring library
is the management of `bstring`s which are a significant improvement over
`'\0'` terminated char buffers. See the accompanying documenation for more
information.

Identifying the Compiler
------------------------

Bstrlib has been tested on the following compilers:

* GNU C/C++
* Microsoft Visual C++
* Watcom C/C++ (32 bit flat)
* Intel's C/C++ compiler (on Windows)
* The GNU C/C++ compiler (on Windows/Linux on x86 and PPC64)
* Borland C++
* Turbo C

There are slight differences in these compilers which requires slight
differences in the implementation of Bstrlib. These are accomodated in the
same sources using `#ifdef/#if defined` on compiler specific macros. To
port Bstrlib to a new compiler not listed above, it is recommended that the
same strategy be followed. If you are unaware of the compiler specific
identifying preprocessor macro for your compiler you might find it
[here](http://predef.sourceforge.net/precomp.html).

> Note: Intel C/C++ on Windows sets the Microsoft identifier: `_MSC_VER`

16-bit vs. 32-bit vs. 64-bit Systems
------------------------------------

Bstrlib has been architected to deal with strings of length between `0` and
`INT_MAX` (inclusive). Since the values of int are never higher than `size_t`
there will be no issue here. Note that on most 64-bit systems `int` is 32-bit.

Dependency on The C-Library
---------------------------

Bstrlib uses the functions `memcpy`, `memmove`, `malloc`, `realloc`, `free`
and `vsnprintf`. Many free standing C compiler implementations that have a
mode in which the C library is not available will typically not include these
functions which will make porting Bstrlib to it onerous. Bstrlib is not
designed for such bare bones compiler environments. This usually includes
compilers that target ROM environments.

Testing a port
--------------

To test that a port compiles correctly do the following:

1. Run `meson test -C build` and ensure that no errors are reported.
2. Run `meson test --wrapper='valgrind --leak-check=full' -C build` and ensure that no errors are reported.

The builds must have zero errors and zero warnings. The result of execution
should be essentially identical on each platform.

Performance
-----------

Different CPU and compilers have different capabilities in terms of
performance. It is possible for Bstrlib to assume performance characteristics
that a platform doesn't have (since it was primarily developed on just one
platform). The goal of Bstrlib is to provide very good performance on all
platforms regardless of this but without resorting to extreme measures (such
as using assembly language, or non-portable intrinsics or library extensions).
