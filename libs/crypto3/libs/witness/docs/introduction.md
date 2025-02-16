# Introduction # {#witness_introduction}

@tableofcontents

Crypto3.witness library extends [[alloc] init]'s Crypto3 C++ cryptography suite and provides a set of witness
encryption schemes implemented in a way C++
standard library implies: concepts, algorithms, predictable behavior, latest standard features support and clean
architecture without compromising security and performance.

Crypto3.witness consists of several parts to review:

* [Manual](@ref witness_manual).
* [Implementation](@ref witness_impl).
* [Concepts](@ref witness_concepts).

## Dependencies ## {#witness_dependencies}

Internal dependencies:

1. [Crypto3.Block](https://github.com/alloc-init/block.git)
2. [Crypto3.Codec](https://github.com/alloc-init/codec.git)

External dependencies:

1. [Boost](https://boost.org) (>= 1.58)