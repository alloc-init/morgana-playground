//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_ARIA_POLICY_HPP
#define CRYPTO3_BLOCK_ARIA_POLICY_HPP

#include <array>

#include <nil/crypto3/block/detail/aria/aria_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<std::size_t KeyBits>
                struct aria_policy;

                template<>
                struct aria_policy<128> : aria_functions<128> {
                    constexpr static const std::size_t rounds = 12;

                    constexpr static const std::size_t key_schedule_words = 4 * (rounds + 1) * CHAR_BIT / word_bits;
                    typedef std::array<word_type, key_schedule_words> key_schedule_type;
                };

                template<>
                struct aria_policy<192> : aria_functions<192> {
                    constexpr static const std::size_t rounds = 14;

                    constexpr static const std::size_t key_schedule_words = 4 * (rounds + 1) * CHAR_BIT / word_bits;
                    typedef std::array<word_type, key_schedule_words> key_schedule_type;
                };

                template<>
                struct aria_policy<256> : aria_functions<256> {
                    constexpr static const std::size_t rounds = 16;

                    constexpr static const std::size_t key_schedule_words = 4 * (rounds + 1) * CHAR_BIT / word_bits;
                    typedef std::array<word_type, key_schedule_words> key_schedule_type;
                };
            } // namespace detail
        } // namespace block
    } // namespace crypto3
} // namespace nil

#endif    // CRYPTO3_BLOCK_ARIA_POLICY_HPP
