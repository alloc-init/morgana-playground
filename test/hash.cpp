//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE hash_based_algebraic_test

#include <string>
#include <tuple>
#include <unordered_map>
#include <sstream>

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/random/hash.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

#include "../src/OtherFile.hpp"
#include "../src/proof_transcript.hpp"

using namespace nil::crypto3;
using namespace morgana::playground;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<typename FieldParams>
            struct print_log_value<typename algebra::fields::detail::element_fp<FieldParams>> {
                void operator()(std::ostream &os, typename algebra::fields::detail::element_fp<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename algebra::fields::detail::element_fp2<FieldParams>> {
                void operator()(std::ostream &os, typename algebra::fields::detail::element_fp2<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename algebra::fields::detail::element_fp6_3over2<FieldParams>> {
                void operator()(std::ostream &os,
                                typename algebra::fields::detail::element_fp6_3over2<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename algebra::fields::detail::element_fp12_2over3over2<FieldParams>> {
                void operator()(std::ostream &os,
                                typename algebra::fields::detail::element_fp12_2over3over2<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream &, P<K, V> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost



BOOST_AUTO_TEST_SUITE(morgana_playground)
BOOST_AUTO_TEST_CASE(proof_transcript) {
    using field_type = typename algebra::curves::mnt4<298>::scalar_field_type;
    using field_value_type = typename field_type::value_type;
    using group_type = typename nil::crypto3::algebra::curves::mnt4<298>::g1_type<>;
    using group_value_type = typename group_type::value_type;
    using f_generator_type = typename random::algebraic_random_device<field_type>;
    using g_generator_type = typename random::algebraic_random_device<group_type>;

    f_generator_type f_gen;
    g_generator_type g_gen;

    field_value_type p_1_fval = f_gen();
    group_value_type p_2_gval = g_gen();
    field_value_type p_3_cval;
    field_value_type p_4_cval;
    field_value_type p_5_fval = f_gen();
    group_value_type p_6_gval = g_gen();
    group_value_type p_7_gval = g_gen();
    field_value_type p_8_cval;

    auto prover_transcript = transcript::start_prover(std::vector<uint8_t>{1, 2, 3});
    prover_transcript.write(p_1_fval);
    prover_transcript.write(p_2_gval);
    p_3_cval = prover_transcript.challenge<field_type>();
    p_4_cval = prover_transcript.challenge<field_type>();
    prover_transcript.write(p_5_fval);
    prover_transcript.write(p_6_gval);
    prover_transcript.write(p_7_gval);
    p_8_cval = prover_transcript.challenge<field_type>();
    auto proof = prover_transcript.end();

    auto verifier_transcript = transcript::start_verifier(std::vector<uint8_t>{1, 2, 3}, proof);
    field_value_type v_1_fval = verifier_transcript.read<field_type>();
    group_value_type v_2_gval = verifier_transcript.read<group_type>();
    field_value_type v_3_cval = verifier_transcript.challenge<field_type>();
    field_value_type v_4_cval = verifier_transcript.challenge<field_type>();
    field_value_type v_5_fval = verifier_transcript.read<field_type>();
    group_value_type v_6_gval = verifier_transcript.read<group_type>();
    group_value_type v_7_gval = verifier_transcript.read<group_type>();
    field_value_type v_8_cval = verifier_transcript.challenge<field_type>();
    verifier_transcript.end();

    BOOST_CHECK_EQUAL(v_1_fval, p_1_fval);
    BOOST_CHECK_EQUAL(v_2_gval, p_2_gval);
    BOOST_CHECK_EQUAL(v_3_cval, p_3_cval);
    BOOST_CHECK_EQUAL(v_4_cval, p_4_cval);
    BOOST_CHECK_EQUAL(v_5_fval, p_5_fval);
    BOOST_CHECK_EQUAL(v_6_gval, p_6_gval);
    BOOST_CHECK_EQUAL(v_7_gval, p_7_gval);
    BOOST_CHECK_EQUAL(v_8_cval, p_8_cval);
}
BOOST_AUTO_TEST_SUITE_END()
