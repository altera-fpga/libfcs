# FPGA Crypto Services Library (LibFCS)

This repository contains the FPGA Crypto Service which is made platform independent.

# FPGA Crypto Services (FCS)
This library provides all the crypto services provided by FPGA to use it over HPS software stack.
Following are the services provided:
- Session management
- Key management
- Vendor Authorized Boot (VAB)
- Counter Set
- Bitstream Pre-authentication
- Provision Data
- Platform Attestation
- Secure Data Object Service (SDOS)
- Random Number Generator
- AES
- SHA2/HMAC
- ECDSA
- ECDH
- HKDF

## Pre-requisite:
1. cmake - 3.24.0 (build configuration tool)
2. arm gnu linaro toolchain (for linux aarch64 platform)
3. make (build tool)

## Compilation steps
cmake -S . -B build -DARCH=linux_aarch64
cmake --build build
This will generate the necessary build files and compile the library for the specified architecture and operating system. The compiled binaries will be available in the build directory.

### Debug build
For debug build please add -DCMAKE_BUILD_TYPE=Debug to the configuration step in build process.
