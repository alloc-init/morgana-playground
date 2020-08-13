//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MODES_DECRYPT_HPP
#define CRYPTO3_MODES_DECRYPT_HPP

#include <nil/crypto3/detail/type_traits.hpp>

#include <nil/crypto3/block/algorithm/block.hpp>

#include <nil/crypto3/block/cipher_value.hpp>
#include <nil/crypto3/block/cipher_state.hpp>

#include <nil/crypto3/block/detail/cipher_modes.hpp>
#include <nil/crypto3/block/detail/key_value.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            template<typename CipherMode>
            using decryption_policy = typename CipherMode::decryption_policy;
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam InputIterator
         * @tparam KeyIterator
         * @tparam OutputIterator
         *
         * @param first
         * @param last
         * @param key_first
         * @param key_last
         * @param out
         *
         * @return
         */
        template<typename CipherMode, typename InputIterator, typename KeyInputIterator, typename OutputIterator>
        OutputIterator decrypt(InputIterator first, InputIterator last, KeyInputIterator key_first,
                               KeyInputIterator key_last, OutputIterator out) {

            typedef typename CipherMode::template bind<block::decryption_policy<CipherMode>>::type DecryptionMode;
            typedef typename block::accumulator_set<DecryptionMode> CipherAccumulator;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::itr_cipher_impl<StreamDecrypterImpl, OutputIterator> DecrypterImpl;

            return DecrypterImpl(
                first, last, std::move(out),
                CipherAccumulator(DecryptionMode(
                    BlockCipher(block::detail::key_value<typename CipherMode::cipher_type>(key_first, key_last)))));
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam InputIterator
         * @tparam KeySinglePassRange
         * @tparam OutputIterator
         *
         * @param first
         * @param last
         * @param key
         * @param out
         *
         * @return
         */
        template<typename CipherMode, typename InputIterator, typename KeySinglePassRange, typename OutputIterator>
        OutputIterator decrypt(InputIterator first, InputIterator last, const KeySinglePassRange &key,
                               OutputIterator out) {

            typedef typename CipherMode::template bind<block::decryption_policy<CipherMode>>::type DecryptionMode;
            typedef typename block::accumulator_set<DecryptionMode> CipherAccumulator;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::itr_cipher_impl<StreamDecrypterImpl, OutputIterator> DecrypterImpl;

            return DecrypterImpl(first, last, std::move(out),
                                 CipherAccumulator(DecryptionMode(
                                     BlockCipher(block::detail::key_value<typename CipherMode::cipher_type>(key)))));
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam InputIterator
         * @tparam OutputAccumulator
         *
         * @param first
         * @param last
         * @param acc
         *
         * @return
         */
        template<typename CipherMode, typename InputIterator,
                 typename OutputAccumulator = typename block::accumulator_set<
                     typename CipherMode::template bind<block::decryption_policy<CipherMode>>::type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            decrypt(InputIterator first, InputIterator last, OutputAccumulator &acc) {

            typedef block::detail::ref_cipher_impl<OutputAccumulator> StreamDecrypterImpl;
            typedef block::detail::range_cipher_impl<StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(first, last, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam SinglePassRange
         * @tparam OutputAccumulator
         *
         * @param r
         * @param acc
         *
         * @return
         */

        template<typename CipherMode, typename SinglePassRange,
                 typename OutputAccumulator = typename block::accumulator_set<
                     typename CipherMode::template bind<typename CipherMode::decryption_policy>::type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            decrypt(const SinglePassRange &r, OutputAccumulator &acc) {

            typedef block::detail::ref_cipher_impl<OutputAccumulator> StreamDecrypterImpl;
            typedef block::detail::range_cipher_impl<StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(r, acc);
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam InputIterator
         * @tparam KeyIterator
         * @tparam CipherAccumulator
         *
         * @param first
         * @param last
         * @param key_first
         * @param key_last
         *
         * @return
         */
        template<typename CipherMode, typename InputIterator, typename KeyInputIterator,
                 typename CipherAccumulator = typename block::accumulator_set<
                     typename CipherMode::template bind<block::decryption_policy<CipherMode>>::type>>
        block::detail::range_cipher_impl<block::detail::value_cipher_impl<CipherAccumulator>>
            decrypt(InputIterator first, InputIterator last, KeyInputIterator key_first, KeyInputIterator key_last) {

            typedef typename CipherMode::template bind<block::decryption_policy<CipherMode>>::type DecryptionMode;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::range_cipher_impl<StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(
                first, last,
                CipherAccumulator(DecryptionMode(
                    BlockCipher(block::detail::key_value<typename CipherMode::cipher_type>(key_first, key_last)))));
        }

        /*!
         * @brief
         *
         * @tparam BlockCipher
         * @tparam InputIterator
         * @tparam KeySinglePassRange
         * @tparam CipherAccumulator
         *
         * @param first
         * @param last
         * @param key
         *
         * @return
         */
        template<typename CipherMode, typename InputIterator, typename KeySinglePassRange,
                 typename CipherAccumulator = typename block::accumulator_set<
                     typename CipherMode::template bind<block::decryption_policy<CipherMode>>::type>>
        block::detail::range_cipher_impl<block::detail::value_cipher_impl<CipherAccumulator>>
            decrypt(InputIterator first, InputIterator last, const KeySinglePassRange &key) {

            typedef typename CipherMode::template bind<block::decryption_policy<CipherMode>>::type DecryptionMode;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::range_cipher_impl<StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(first, last,
                                 CipherAccumulator(DecryptionMode(
                                     BlockCipher(block::detail::key_value<typename CipherMode::cipher_type>(key)))));
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam SinglePassRange
         * @tparam KeyRange
         * @tparam OutputIterator
         *
         * @param rng
         * @param key
         * @param out
         *
         * @return
         */
        template<typename CipherMode, typename SinglePassRange, typename KeyPassRange, typename OutputIterator>
        OutputIterator decrypt(const SinglePassRange &rng, const KeyPassRange &key, OutputIterator out) {

            typedef typename CipherMode::template bind<block::decryption_policy<CipherMode>>::type DecryptionMode;
            typedef typename block::accumulator_set<DecryptionMode> CipherAccumulator;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::itr_cipher_impl<StreamDecrypterImpl, OutputIterator> DecrypterImpl;

            return DecrypterImpl(rng, std::move(out),
                                 CipherAccumulator(DecryptionMode(
                                     BlockCipher(block::detail::key_value<typename CipherMode::cipher_type>(key)))));
        }

        /*!
         * @brief
         *
         * @tparam BlockCipher
         * @tparam SinglePassRange
         * @tparam KeyPassRange
         * @tparam OutputRange
         *
         * @param rng
         * @param key
         * @param out
         *
         * @return
         */
        template<typename CipherMode, typename SinglePassRange, typename KeyPassRange, typename OutputRange>
        OutputRange &decrypt(const SinglePassRange &rng, const KeyPassRange &key, OutputRange &out) {

            typedef typename CipherMode::template bind<block::decryption_policy<CipherMode>>::type DecryptionMode;
            typedef typename block::accumulator_set<DecryptionMode> CipherAccumulator;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::range_cipher_impl<StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(rng, std::move(out),
                                 CipherAccumulator(DecryptionMode(
                                     BlockCipher(block::detail::key_value<typename CipherMode::cipher_type>(key)))));
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam SinglePassRange
         * @tparam KeyRange
         * @tparam CipherAccumulator
         *
         * @param r
         * @param key
         *
         * @return
         */

        template<typename BlockCipher, typename SinglePassRange, typename KeyPassRange,
                 typename CipherAccumulator = typename block::accumulator_set<typename block::modes::isomorphic<
                     BlockCipher, block::nop_padding>::template bind<block::decryption_policy<BlockCipher>>::type>>
        block::detail::range_cipher_impl<block::detail::value_cipher_impl<CipherAccumulator>>
            decrypt(const SinglePassRange &r, const KeyPassRange &key) {

            typedef typename block::modes::isomorphic<BlockCipher, block::nop_padding>::template bind<
                block::decryption_policy<BlockCipher>>::type DecryptionMode;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::range_cipher_impl<StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(
                r, CipherAccumulator(DecryptionMode(BlockCipher(block::detail::key_value<BlockCipher>(key)))));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
