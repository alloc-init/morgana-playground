//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ZK_R1CS_GG_PPZKSNARK_IPP2_GENERATOR_HPP
#define CRYPTO3_ZK_R1CS_GG_PPZKSNARK_IPP2_GENERATOR_HPP

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/generator.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType>
                class r1cs_gg_ppzksnark_aggregate_generator {
                    typedef detail::r1cs_gg_ppzksnark_basic_policy<CurveType> policy_type;

                    typedef typename CurveType::pairing pairing_policy;
                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename CurveType::g1_type g1_type;
                    typedef typename CurveType::g2_type g2_type;
                    typedef typename CurveType::gt_type gt_type;

                public:
                    typedef typename policy_type::constraint_system_type constraint_system_type;
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input_type;

                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;
                    typedef typename policy_type::aggregate_verification_key_type aggregate_verification_key_type;

                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::aggregate_keypair_type aggregate_keypair_type;
                    typedef typename policy_type::proof_type proof_type;
                    typedef typename policy_type::aggregate_proof_type aggregate_proof_type;

                    template<typename DistributionType =
                                 boost::random::uniform_int_distribution<typename scalar_field_type::modulus_type>,
                             typename GeneratorType = boost::random::mt19937>
                    static inline aggregate_keypair_type process(const constraint_system_type &constraint_system) {

                        auto [alpha_g1,
                              beta_g1,
                              beta_g2,
                              delta_g1,
                              delta_g2,
                              gamma_g2,
                              A_query,
                              B_query,
                              H_query,
                              L_query,
                              r1cs_copy,
                              alpha_g1_beta_g2,
                              gamma_ABC_g1] = std::move(basic_process(constraint_system));

                        aggregate_verification_key_type vk(alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_ABC_g1);

                        proving_key_type pk(std::move(alpha_g1),
                                            std::move(beta_g1),
                                            std::move(beta_g2),
                                            std::move(delta_g1),
                                            std::move(delta_g2),
                                            std::move(A_query),
                                            std::move(B_query),
                                            std::move(H_query),
                                            std::move(L_query),
                                            std::move(r1cs_copy));

                        return {std::move(pk), std::move(vk)};
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_R1CS_GG_PPZKSNARK_IPP2_GENERATOR_HPP
