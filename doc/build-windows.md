WINDOWS BUILD NOTES
+AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0APQ-

Some notes on how to build PrimeStone for Windows.

Most developers use cross-compilation from Ubuntu to build executables for
Windows. This is also used to build the release binaries.

Building on Windows itself is possible (for example using msys / mingw-w64),
but no one documented the steps to do this. If you are doing this, please contribute them.

Cross-compilation
-------------------

These steps can be performed on, for example, an Ubuntu VM. The depends system
will also work on other Linux distributions, however the commands for
installing the toolchain will be different.

First install the toolchains:

    sudo apt-get install gmingw-w64-i686 mingw-w64-i686-dev gmingw-w64-x86-64 mingw-w64-x86-64-dev

To build executables for Windows 32-bit:

    cd depends
    make HOST+AD0-i686-w64-mingw32 -j4
    cd ..
    ./configure --prefix+AD0AYA-pwd+AGA-/depends/i686-w64-mingw32
    make

To build executables for Windows 64-bit:

    cd depends
    make HOST+AD0-x86+AF8-64-w64-mingw32 -j4
    cd ..
    ./configure --prefix+AD0AYA-pwd+AGA-/depends/x86+AF8-64-w64-mingw32
    make

For further documentation on the depends system see +AFs-README.md+AF0-(../depends/README.md) in the depends directory.

