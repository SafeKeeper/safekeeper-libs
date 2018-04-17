SafeKeeper - Protecting Web passwords using Trusted Execution Environments
==========================================================================

Introduction
------------

SafeKeeper is a server-side technology for protecting password databases. SafeKeeper's server-side password protection service is a drop-in replacement for standard password hashing functions. It computes a cipher-based message authentication code (CMAC) on passwords before they are stored in the
database. An adversary must obtain the CMAC key in order to perform offline guessing attacks against a stolen password database. SafeKeeper generates and protects this key within a Trusted Execution Environment, realized using Intel's Software Guard Extensions (SGX) technology.

This repository holds the libraries to build the SafeKeeper server.

### Prerequisites

- Install SGX SDK:
  * Download [Intel SGX SDK for Linux](https://github.com/01org/linux-sgx)
  * By default Makefile's expect to have SDK sources in ``~/git/sgx/linux-sgx``.
  * If the repository is in a different directory, change TOP-DIR variable in Makefile.
  * The variable is referenced from Makefile's in `lib_tke` and `lib_uke`, thus if using relative paths make sure to add the correct number of `..`.


Build
-----

Run `make`.
