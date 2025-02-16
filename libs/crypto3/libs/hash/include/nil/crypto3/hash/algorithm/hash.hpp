//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_HPP
#define CRYPTO3_HASH_HPP

#ifdef __ZKLLVM__
#else

#include <nil/crypto3/detail/type_traits.hpp>
#include <nil/crypto3/hash/hash_value.hpp>
#include <nil/crypto3/hash/hash_state.hpp>
#include <nil/crypto3/hash/type_traits.hpp>

#endif

namespace nil {
    namespace crypto3 {
#ifdef __ZKLLVM__
        template <class HashType>
        typename HashType::block_type hash(typename HashType::block_type block0, typename HashType::block_type block1) {
           return typename HashType::process()(block0, block1);
        }
#else
        /*!
         * @defgroup hashes Hash Functions & Checksums
         *
         * @brief Hash functions are one-way functions, which map data of arbitrary size to a
         * fixed output length. Most of the hashes functions in crypto3 are designed to be
         * cryptographically secure, which means that it is computationally infeasible to
         * create a collision (finding two inputs with the same hashes) or preimages (given a
         * hashes output, generating an arbitrary input with the same hashes). But note that
         * not all such hashes functions meet their goals, in particular @ref nil::crypto3::hashes::md4 "MD4" and @ref
         * nil::crypto3::hashes::md5 "MD5" are trivially broken. However they are still included due to their wide
         * adoption in various protocols.
         *
         * Using a hashes function is typically split into three stages: initialization,
         * update, and finalization (often referred to as a IUF interface). The
         * initialization stage is implicit: after creating a hashes function object, it is
         * ready to process data. Then update is called one or more times. Calling update
         * several times is equivalent to calling it once with all of the arguments
         * concatenated. After completing a hashes computation (eg using ``final``), the
         * internal state is reset to begin hashing a new message.
         *
         * @defgroup hash_algorithms Algorithms
         * @ingroup hashes
         * @brief Algorithms are meant to provide hashing interface similar to STL algorithms' one.
         */

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam InputIterator
         * @tparam OutputIterator
         *
         * @param first
         * @param last
         * @param out
         *
         * @return
         */
        template<typename HashType, typename InputIterator, typename OutputIterator>
        typename std::enable_if<!boost::accumulators::detail::is_accumulator_set<OutputIterator>::value,
            OutputIterator>::type
        hash(InputIterator first, InputIterator last, OutputIterator out) {
            typedef accumulator_set<HashType> HashAccumulator;

            typedef hashes::detail::value_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::itr_hash_impl<StreamHashImpl, OutputIterator> HashImpl;

            return HashImpl(first, last, std::move(out), HashAccumulator());
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam InputIterator
         * @tparam HashAccumulator
         *
         * @param first
         * @param last
         * @param sh
         *
         * @return
         */
        template<typename HashType, typename InputIterator, typename HashAccumulator = accumulator_set<HashType>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<HashAccumulator>::value,
            HashAccumulator>::type
        hash(InputIterator first, InputIterator last, HashAccumulator &sh) {
            typedef hashes::detail::ref_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::range_hash_impl<StreamHashImpl> HashImpl;

            return HashImpl(first, last, sh);
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam InputIterator
         * @tparam HashAccumulator
         *
         * @param first
         * @param last
         *
         * @return
         */
        template<typename HashType, typename InputIterator, typename HashAccumulator = accumulator_set<HashType>>
        hashes::detail::range_hash_impl<hashes::detail::value_hash_impl<typename std::enable_if<
            boost::accumulators::detail::is_accumulator_set<HashAccumulator>::value, HashAccumulator>::type>>
        hash(InputIterator first, InputIterator last) {
            typedef hashes::detail::value_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::range_hash_impl<StreamHashImpl> HashImpl;

            return HashImpl(first, last, HashAccumulator());
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam SinglePassRange
         * @tparam OutputIterator
         *
         * @param rng
         * @param out
         *
         * @return
         */
        template<typename HashType, typename SinglePassRange, typename OutputIterator>
        typename std::enable_if<::nil::crypto3::detail::is_iterator<OutputIterator>::value, OutputIterator>::type
        hash(const SinglePassRange &rng, OutputIterator out) {
            typedef accumulator_set<HashType> HashAccumulator;

            typedef hashes::detail::value_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::itr_hash_impl<StreamHashImpl, OutputIterator> HashImpl;

            return HashImpl(rng, std::move(out), HashAccumulator());
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam SinglePassRange
         * @tparam HashAccumulator
         *
         * @param rng
         * @param sh
         *
         * @return
         */
        template<typename HashType, typename SinglePassRange, typename HashAccumulator = accumulator_set<HashType>>
        typename std::enable_if_t<boost::accumulators::detail::is_accumulator_set<HashAccumulator>::value &&
                                  detail::is_range<SinglePassRange>::value,
            HashAccumulator>
        hash(const SinglePassRange &rng, HashAccumulator &sh) {
            typedef hashes::detail::ref_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::range_hash_impl<StreamHashImpl> HashImpl;

            return HashImpl(rng, sh);
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam SinglePassRange
         * @tparam HashAccumulator
         *
         * @param r
         *
         * @return
         */
        template<typename HashType, typename SinglePassRange, typename HashAccumulator = accumulator_set<HashType>>
        typename std::enable_if<detail::is_range<SinglePassRange>::value, hashes::detail::range_hash_impl<
            hashes::detail::value_hash_impl<HashAccumulator>>>::type
        hash(const SinglePassRange &r) {
            typedef hashes::detail::value_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::range_hash_impl<StreamHashImpl> HashImpl;

            return HashImpl(r, HashAccumulator());
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam T
         * @tparam OutputIterator
         *
         * @param rng
         * @param out
         *
         * @return
         */
        template<typename HashType, typename T, typename OutputIterator>
        typename std::enable_if<::nil::crypto3::detail::is_iterator<OutputIterator>::value, OutputIterator>::type
        hash(std::initializer_list<T> list, OutputIterator out) {
            typedef accumulator_set<HashType> HashAccumulator;

            typedef hashes::detail::value_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::itr_hash_impl<StreamHashImpl, OutputIterator> HashImpl;

            return HashImpl(list, std::move(out), HashAccumulator());
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam T
         * @tparam HashAccumulator
         *
         * @param rng
         * @param sh
         *
         * @return
         */
        template<typename HashType, typename T, typename HashAccumulator = accumulator_set<HashType>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<HashAccumulator>::value,
            HashAccumulator>::type
        hash(std::initializer_list<T> rng, HashAccumulator &sh) {
            typedef hashes::detail::ref_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::range_hash_impl<StreamHashImpl> HashImpl;

            return HashImpl(rng, sh);
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam T
         * @tparam HashAccumulator
         *
         * @param r
         *
         * @return
         */
        template<typename HashType, typename T, typename HashAccumulator = accumulator_set<HashType>>
        hashes::detail::range_hash_impl<hashes::detail::value_hash_impl<HashAccumulator>>
        hash(std::initializer_list<T> r) {
            typedef hashes::detail::value_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::range_hash_impl<StreamHashImpl> HashImpl;

            return HashImpl(r, HashAccumulator());
        }

        /*!
        * @brief Hashes a single value by wrapping it into an array and processing it as a range.
        *
        * @ingroup hash_algorithms
        *
        * @tparam Hash The hash function to be used.
        * @tparam T The type of the value being hashed.
        * @tparam OutputIterator The type of the output iterator.
        *
        * @param value The single value to be hashed.
        * @param out The iterator to which the hash will be written.
        *
        * @return The updated OutputIterator after processing the value.
        */
        template<typename HashType, typename T, typename OutputIterator>
        typename std::enable_if<
            ::nil::crypto3::detail::is_iterator<OutputIterator>::value && !detail::is_range<T>::value,
            OutputIterator>::type
        hash(T value, OutputIterator out) {
            typedef accumulator_set<HashType> HashAccumulator;

            typedef hashes::detail::value_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::itr_hash_impl<StreamHashImpl, OutputIterator> HashImpl;

            std::array<T, 1> wrapped_value = {value};

            return HashImpl(wrapped_value, std::move(out), HashAccumulator());
        }

        /*!
        * @brief Hashes a single value by wrapping it into an array and processing it as a range.
        *
        * @ingroup hash_algorithms
        *
        * @tparam Hash The hash function to be used.
        * @tparam T The type of the value being hashed.
        * @tparam HashAccumulator The type of the accumulator, defaulted to accumulator_set<Hash>.
        *
        * @param value The single value to be hashed.
        * @param sh The accumulator to which the hash will be added.
        *
        * @return The updated HashAccumulator after processing the value.
        */
        template<typename HashType, typename T, typename HashAccumulator = accumulator_set<HashType>>
        typename std::enable_if_t<
            boost::accumulators::detail::is_accumulator_set<HashAccumulator>::value && !detail::is_range<T>::value,
            HashAccumulator
        >
        hash(T value, HashAccumulator &sh) {
            typedef hashes::detail::ref_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::range_hash_impl<StreamHashImpl> HashImpl;

            std::array<T, 1> wrapped_value = {value};

            return HashImpl(wrapped_value, sh);
        }

        /*!
        * @brief Hashes a single value by wrapping it into an array and processing it as a range.
        *
        * @ingroup hash_algorithms
        *
        * @tparam Hash The hash function to be used.
        * @tparam T The type of the value being hashed.
        * @tparam HashAccumulator The type of the accumulator, defaulted to accumulator_set<Hash>.
        *
        * @param value The single value to be hashed.
        *
        * @return
        */
        template<typename HashType, typename T, typename HashAccumulator = accumulator_set<HashType>>
        typename std::enable_if_t<
            boost::accumulators::detail::is_accumulator_set<HashAccumulator>::value && !detail::is_range<T>::value,
            hashes::detail::range_hash_impl<hashes::detail::value_hash_impl<HashAccumulator>>>
        hash(T value) {
            typedef hashes::detail::value_hash_impl<HashAccumulator> StreamHashImpl;
            typedef hashes::detail::range_hash_impl<StreamHashImpl> HashImpl;

            std::array<T, 1> wrapped_value = {value};

            return HashImpl(wrapped_value, HashAccumulator());
        }

#endif    // #ifdef __ZKLLVM__ else
    } // namespace crypto3
} // namespace nil

#endif    // CRYPTO3_HASH_HPP
