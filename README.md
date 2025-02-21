## Installation instructions

You will need BOOST installed.

In the following command change `-DBOOST_ROOT=` parameter to your Boost installation location (tested on 1.87 version), and `-DCMAKE_CXX_COMPILER=` to your version of Clang.

Currently, you also need cmaketools installed.

```
mkdir build && cd build
cmake -G "Unix Makefiles" -DBOOST_ROOT=/usr -DCMAKE_CXX_COMPILER="clang++-18" -DCMAKE_INSTALL_PREFIX=~/.cmake/llvm/zkllvm/debug -DCMAKE_BUILD_TYPE=Debug -DBUILD_WITH_BOOST_STATIC_LIBS=FALSE -DBUILD_TESTS=TRUE -DCMAKE_ENABLE_TESTS=TRUE -DCMAKE_CXX_STANDARD=20 -DBoost_NO_SYSTEM_PATHS=ON -DBUILD_EXAMPLES=TRUE ..
```

### Subtree system usage

`TODO`
