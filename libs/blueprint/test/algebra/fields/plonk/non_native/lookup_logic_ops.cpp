//---------------------------------------------------------------------------//
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_non_native_logic_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/lookup_logic_ops.hpp>

#include <map>

#include "../../../../test_plonk_component.hpp"

using namespace nil;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

template <typename BlueprintFieldType, typename ComponentType>
void test_logic_component(std::map<std::array<bool, 2>, bool> expected_mapping) {
    using field_value_type = typename BlueprintFieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<field_type>;
    std::size_t WitnessColumns = 3;
    std::size_t PublicInputColumns = 1;
    std::size_t ConstantColumns = 4;
    std::size_t SelectorColumns = 4;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t lambda = 1;

    std::array<std::uint32_t, 2 + 1> witnesses;
    for (std::uint32_t i = 0; i < 2 + 1; i++) {
        witnesses[i] = i;
    }
    ComponentType component_instance(witnesses);

    typename ComponentType::input_type instance_input;
    for (std::uint32_t i = 0; i < 2; i++) {
        instance_input.input[i] = var(0, i, false, var::column_type::public_input);
    }

    auto result_check = [](field_value_type expected_result) {
        return [expected_result](AssignmentType &assignment,
            typename ComponentType::result_type &real_res) {
                assert(var_value(assignment, real_res.output) == expected_result);
            };
    };

    std::vector<field_value_type> public_input;
    public_input.resize(2);

    for (auto item : expected_mapping) {
        for (std::size_t i = 0; i < 2; i++) {
            public_input[i] = item.first[i] ? 1 : 0;
        }

        crypto3::test_component<ComponentType, BlueprintFieldType, hash_type, lambda>(
            component_instance, desc, public_input, result_check(item.second ? 1 : 0), instance_input);
    }
}


BOOST_AUTO_TEST_CASE(blueprint_non_native_lookup_logic_and_test) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<field_type>;
    using component_type = blueprint::components::lookup_logic_and<ArithmetizationType>;

    std::map<std::array<bool, 2>, bool> expected_mapping = {
        {{false, false}, false}, {{false, true}, false}, {{true, false}, false}, {{true, true}, true},
    };
    test_logic_component<field_type, component_type>(expected_mapping);
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_lookup_logic_xor_test) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<field_type>;
    using component_type = blueprint::components::lookup_logic_xor<ArithmetizationType>;

    std::map<std::array<bool, 2>, bool> expected_mapping = {
        {{false, false}, false}, {{false, true}, true}, {{true, false}, true}, {{true, true}, false},
    };
    test_logic_component<field_type, component_type>(expected_mapping);
}

BOOST_AUTO_TEST_SUITE_END()