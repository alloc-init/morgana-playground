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

#define BOOST_TEST_MODULE blueprint_plonk_field_operations_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/division.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/subtraction.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/multiplication_by_constant.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/division_or_zero.hpp>

#include "../../../test_plonk_component.hpp"

using namespace nil;

template <typename FieldType>
void test_add(std::vector<typename FieldType::value_type> public_input){
    using BlueprintFieldType = FieldType;
    constexpr std::size_t WitnessColumns = 3;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::addition<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input)};

    typename BlueprintFieldType::value_type expected_res = public_input[0] + public_input[1];

    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
            #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "add test: " << "\n";
            std::cout << "input   : " << public_input[0].data << " " << public_input[1].data << "\n";
            std::cout << "expected: " << expected_res.data    << "\n";
            std::cout << "real    : " << var_value(assignment, real_res.output).data << "\n\n";
            #endif
            assert(expected_res == var_value(assignment, real_res.output));
    };

    component_type component_instance({0, 1, 2},{},{});

    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda> (
        component_instance, desc, public_input, result_check, instance_input);
    nil::crypto3::test_empty_component<component_type, BlueprintFieldType, hash_type, Lambda> (
        component_instance, desc, public_input, result_check, instance_input);
}

template <typename FieldType>
void test_sub(std::vector<typename FieldType::value_type> public_input){
    using BlueprintFieldType = FieldType;
    constexpr std::size_t WitnessColumns = 3;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::subtraction<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input)};

    typename BlueprintFieldType::value_type expected_res = public_input[0] - public_input[1];

    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
            #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "sub test: " << "\n";
            std::cout << "input   : " << public_input[0].data << " " << public_input[1].data << "\n";
            std::cout << "expected: " << expected_res.data    << "\n";
            std::cout << "real    : " << var_value(assignment, real_res.output).data << "\n\n";
            #endif
            assert(expected_res == var_value(assignment, real_res.output));
    };

    component_type component_instance({0, 1, 2},{},{});

    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda> (
        component_instance, desc, public_input, result_check, instance_input);
    nil::crypto3::test_empty_component<component_type, BlueprintFieldType, hash_type, Lambda> (
        component_instance, desc, public_input, result_check, instance_input);
}

template <typename FieldType>
void test_mul(std::vector<typename FieldType::value_type> public_input){
    using BlueprintFieldType = FieldType;
    constexpr std::size_t WitnessColumns = 3;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::multiplication<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input)};

    typename BlueprintFieldType::value_type expected_res = public_input[0] * public_input[1];

    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
            #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "mul test: " << "\n";
            std::cout << "input   : " << public_input[0].data << " " << public_input[1].data << "\n";
            std::cout << "expected: " << expected_res.data    << "\n";
            std::cout << "real    : " << var_value(assignment, real_res.output).data << "\n\n";
            #endif
            assert(expected_res == var_value(assignment, real_res.output));
    };

    component_type component_instance({0, 1, 2},{},{});

    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda> (
        component_instance, desc, public_input, result_check, instance_input);
    nil::crypto3::test_empty_component<component_type, BlueprintFieldType, hash_type, Lambda> (
        component_instance, desc, public_input, result_check, instance_input);
}

template <typename FieldType>
void test_mul_by_const(std::vector<typename FieldType::value_type> public_input,
    typename FieldType::value_type y){
    using BlueprintFieldType = FieldType;
    constexpr std::size_t WitnessColumns = 2;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 1;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::mul_by_constant<ArithmetizationType, BlueprintFieldType>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input)};

    typename BlueprintFieldType::value_type expected_res = public_input[0] * y;

    auto result_check = [&expected_res, public_input, y](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
            #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "mul_by_const test: " << "\n";
            std::cout << "input   : " << public_input[0].data << " " << y.data << "\n";
            std::cout << "expected: " << expected_res.data    << "\n";
            std::cout << "real    : " << var_value(assignment, real_res.output).data << "\n\n";
            #endif
            assert(expected_res == var_value(assignment, real_res.output));
    };

    component_type component_instance({0, 1},{0},{},y);

    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda> (
        component_instance, desc, public_input, result_check, instance_input);
    nil::crypto3::test_empty_component<component_type, BlueprintFieldType, hash_type, Lambda> (
        component_instance, desc, public_input, result_check, instance_input);
}

template <typename FieldType>
void test_div(std::vector<typename FieldType::value_type> public_input,
    typename FieldType::value_type expected_res){
    using BlueprintFieldType = FieldType;
    constexpr std::size_t WitnessColumns = 4;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::division<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input)};

    auto result_check = [&expected_res](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
            assert(expected_res == var_value(assignment, real_res.output));
    };

    component_type component_instance({0, 1, 2, 3},{},{});

    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda> (
        component_instance, desc, public_input, result_check, instance_input);
    nil::crypto3::test_empty_component<component_type, BlueprintFieldType, hash_type, Lambda> (
        component_instance, desc, public_input, result_check, instance_input);
}

template <typename FieldType>
void test_div_or_zero(std::vector<typename FieldType::value_type> public_input){
    using BlueprintFieldType = FieldType;
    constexpr std::size_t WitnessColumns = 5;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::division_or_zero<ArithmetizationType, BlueprintFieldType>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input)};

    typename FieldType::value_type expected_res;
    if (public_input[1] != FieldType::value_type::zero()) {
        expected_res = public_input[0] * public_input[1].inversed();
    } else {
        expected_res = FieldType::value_type::zero();
    }

    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
            #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "div_or_zero test: " << "\n";
            std::cout << "input   : " << public_input[0].data << " " << public_input[1].data << "\n";
            std::cout << "expected: " << expected_res.data    << "\n";
            std::cout << "real    : " << var_value(assignment, real_res.output).data << "\n\n";
            #endif
            assert(expected_res == var_value(assignment, real_res.output));
    };

    component_type component_instance({0, 1, 2, 3, 4},{},{});

    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda> (
        component_instance, desc, public_input, result_check, instance_input);
    nil::crypto3::test_empty_component<component_type, BlueprintFieldType, hash_type, Lambda> (
        component_instance, desc, public_input, result_check, instance_input);
}

template <typename FieldType>
void test_5_components(int i, int j) {
    typename FieldType::value_type i_fe = i > 0 ? i : FieldType::modulus - std::abs(i);
    typename FieldType::value_type j_fe = j > 0 ? j : FieldType::modulus - std::abs(j);

    test_add<FieldType>({i_fe, j_fe});
    test_sub<FieldType>({i_fe, j_fe});
    test_mul<FieldType>({i_fe, j_fe});
    test_mul_by_const<FieldType>({i_fe}, j_fe);
    test_div_or_zero<FieldType>({i_fe, j_fe});
}

template <typename FieldType>
void test_5_components_on_random_data() {
    nil::crypto3::random::algebraic_engine<FieldType> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    typename FieldType::value_type i = generate_random();
    typename FieldType::value_type j = generate_random();

    test_add<FieldType>({i, j});
    test_sub<FieldType>({i, j});
    test_mul<FieldType>({i, j});
    test_mul_by_const<FieldType>({i}, j);
    test_div_or_zero<FieldType>({i, j});
}

template <typename FieldType, std::size_t RandomTestsAmount>
void field_operations_test() {
    for (int i = -2; i < 3; i++){
        for (int j = -2; j < 3; j++){
            test_5_components<FieldType>(i, j);
        }
    }

    for (std::size_t i = 0; i < RandomTestsAmount; i++){
        test_5_components_on_random_data<FieldType>();
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_field_operations_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    field_operations_test<field_type, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_field_operations_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    field_operations_test<field_type, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_field_operations_test_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
    field_operations_test<field_type, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
