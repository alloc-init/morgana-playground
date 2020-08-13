//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_BN128_FQ2_PARAMS_HPP
#define ALGEBRA_FIELDS_BN128_FQ2_PARAMS_HPP

#include <nil/algebra/fields/detail/params/params.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {
                BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(254)

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                struct arithmetic_params<bn128_fq2<ModulusBits, GeneratorBits>> : public params<bn128_fq2<ModulusBits, GeneratorBits>> {
                private:
                    typedef params<bn128_fq2<ModulusBits, GeneratorBits>> policy_type;
                public:
                    constexpr static const typename policy_type::number_type q =
                        10944121435919637611123202872628637544348155578648911831344518947322613104291_cppui254;
                };
            
            }    // namespace detail
        }    // namespace fields
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_BN128_FQ2_PARAMS_HPP
