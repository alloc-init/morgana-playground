# Witness Encryption for [[alloc] init]'s Cryptography Suite

[![Build Status](https://travis-ci.com/NilFoundation/hash.svg?branch=master)](https://travis-ci.com/NilFoundation/hash)

Wirnessl Encryption for [[alloc] init]'s cryptography suite offering different
state-of-the-art implementations of functional encryption schemes, specifically
FE schemes for _linear_ polynomials (e.g. _inner products_).

To quickly get familiar with FE, read a short and very high-level introduction on
our [Introductory Wiki page](https://github.com/fentec-project/gofe/wiki/Introduction-to-FE).

- [Using CiFEr in your project](#using-cifer-in-your-project)
    * [Select the FE scheme](#select-the-fe-scheme)
    * [Configure selected scheme](#configure-selected-scheme)
    * [Prepare input data](#prepare-input-data)
    * [Use the scheme (examples)](#use-the-scheme-(examples))

<!-- tocstop -->

## Building

This library uses Boost CMake build modules (https://github.com/BoostCMake/cmake_modules.git). To actually include this
library in a project it is required to:

1. Add [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) as submodule to target project repository.
2. Add all the internal dependencies using [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) as
   submodules to target project repository.
3. Initialize parent project with [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) (Look
   at [crypto3](https://github.com/alloc-init/crypto3.git) for the example)

## Dependencies

### Internal

* [Algebra](https://github.com/alloc-init/crypto3-algebra.git)
* [Block Ciphers](https://github.com/alloc-init/crypto3-block.git)

### External

* [Boost](https://boost.org) (>= 1.74)