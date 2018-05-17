SafeKeeper - Protecting Web passwords using Trusted Execution Environments
==========================================================================

Introduction
------------

SafeKeeper is a server-side technology for protecting password databases. SafeKeeper's server-side password protection service is a drop-in replacement for standard password hashing functions. It computes a cipher-based message authentication code (CMAC) on passwords before they are stored in the
database. An adversary must obtain the CMAC key in order to perform offline guessing attacks against a stolen password database. SafeKeeper generates and protects this key within a Trusted Execution Environment, realized using Intel's Software Guard Extensions (SGX) technology.

This repository holds the some of the libraries to build the SafeKeeper server.
The other libraries can be found in [SSGAalto utils repository](https://github.com/SSGAalto/sgx-utils).

### Prerequisites

- Get SSG Aalto libraries:
  * Build `lib_tke` and `lib_uke` libraries and copy them to this repository.
  * Follow the instructions in the SSGAalto utils README.

- If PHP extension is needed, install the dependencies for PHP-CPP library

Build
-----

Run `make` and `make php` for the PHP library.
