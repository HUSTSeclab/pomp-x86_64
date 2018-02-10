# reverse-from-coredump

Reverse Execution From CoreDump

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

**Make sure the binary file and all the corresponding library files are in the `binary_path`**

### Test

```
$ ./src/reverse testsuites/latex2rtf/core testsuites/latex2rtf/ testsuites/latex2rtf/inst.reverse testsuites/latex2rtf/reginfo.reverse testsuites/latex2rtf/xmm.log testsuites/latex2rtf/summary.lib
```

### Clean

```
$ make clean
$ make distclean
```

### ToDo List

 - [ ] implement handlers for instructions in x86/x86_64
 - [ ] check x86/x86_64 in the runtime and decide which handler to use
 - [ ] implement the APIs used in the **alias verification**
 - [ ] implement the APIs used in the **backward taint analysis**
