# reverse-from-coredump
Reverse Execution From CoreDump

**Note that our tool only supports 32 bit now.**

## Prerequirement

### libelf

    $ sudo apt-get install libelf1 libelf-dev

library to read and write ELF files

### capstone

Building from [Source Code](https://github.com/aquynh/capstone):

**For Linux:**

```
$ ./make.sh
sudo make install
```

### autoconf / automake

    $ sudo apt-get install autoconf automake

## Building

```
$ ./autogen.sh
$ ./configure
$ make
```

## Usage

    $ ./src/reverse coredump binary_path inversed_instruction_trace inverse_reginfo xmm_log summary_lib

**Make sure binary file and all the library files are in the binary_path**

### Test

```
$ ./src/reverse testsuites/latex2rtf/core testsuites/latex2rtf/ testsuites/latex2rtf/inst.reverse testsuites/latex2rtf/reginfo.reverse testsuites/latex2rtf/xmm.log testsuites/latex2rtf/summary.lib
```

### Clean

```
$ make clean
$ make distclean
```
