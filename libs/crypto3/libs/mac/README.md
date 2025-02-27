# Message Authentication Codes for [[alloc] init]'s Cryptography Suite

Message authentication codes for [[alloc] init]'s cryptography suite.

## Building

This library uses Boost CMake build modules (https://github.com/BoostCMake/cmake_modules.git). To actually include this
library in a project it is required to:

1. Add [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) as submodule to target project repository.
2. Add all the internal dependencies using [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) as
   submodules to target project repository.
3. Initialize parent project with [CMake Modules](https://github.com/BoostCMake/cmake_modules.git)(Look
   at [crypto3](https://github.com/alloc-init/crypto3.git) for the example)

## Dependencies

### Internal

* [Block Ciphers](https://github.com/alloc-init/block.git)
* [Hashes](https://github.com/alloc-init/hash.git)

### External

* [Boost](https://boost.org) (>= 1.58)
