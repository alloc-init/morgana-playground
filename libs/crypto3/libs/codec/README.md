# Encoding for [[alloc] init]'s Cryptography Suite

[![Build Status](https://travis-ci.com/NilFoundation/codec.svg?branch=master)](https://travis-ci.com/NilFoundation/codec)

Encoding for [[alloc] init]'s cryptography suite.

## Building

This library uses Boost CMake build modules (https://github.com/BoostCMake/cmake_modules.git).
To actually include this library in a project it is required to:

1. Add [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) as submodule to target project repository.
2. Add all the internal dependencies using [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) as
   submodules to target project repository.
3. Initialize parent project with [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) (Look
   at [crypto3](https://github.com/alloc-init/crypto3.git) for the example)

## Dependencies

### Internal

* [Boost.Predef](https://github.com/alloc-init/predef.git) (until https://github.com/boostorg/predef/pull/108
  and https://github.com/boostorg/predef/pull/107 are accepted)
* [Boost.Config](https://github.com/alloc-init/config.git) (until https://github.com/boostorg/config/pull/338
  and https://github.com/boostorg/config/pull/339 are accepted)

### External

* [Boost](https://boost.org) (>= 1.58)