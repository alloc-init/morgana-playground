//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the RANGE component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_RANGE_EDWARD25519_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_RANGE_EDWARD25519_HPP

#include <nil/crypto3/algebra/fields/curve25519/base_field.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/component_stretcher.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            // Input:
            // Output:
            /* a0 a1 a2 a3 a'0 a'1 a'2 a'3 xi
                a'4 a'5 a'6 a'7 a'8 a'9 a'10 a'11 c
            */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class range;

            template<typename BlueprintFieldType>
            class range<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                        typename crypto3::algebra::fields::curve25519_base_field,
                        basic_non_native_policy<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType> {

                using operating_field_type = crypto3::algebra::fields::curve25519_base_field;
                using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return range::gates_amount;
                    }
                };

                static gate_manifest& get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(9)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    return 2;
                }
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                constexpr static const std::size_t gates_amount = 1;

                struct input_type {
                    typename non_native_policy_type::template field<operating_field_type>::non_native_var_type
                        input;    // 66,66,66,57 bits

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {input[0], input[1], input[2], input[3]};
                    }
                };

                struct result_type {
                    result_type(const range &component, std::uint32_t start_row_index) {}

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {};
                    }
                };

                template<typename ContainerType>
                explicit range(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                range(WitnessContainerType witness, ConstantContainerType constant,
                      PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                range(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                      std::initializer_list<typename component_type::constant_container_type::value_type>
                          constants,
                      std::initializer_list<typename component_type::public_input_container_type::value_type>
                          public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType>
            using plonk_ed25519_range =
                range<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                      typename crypto3::algebra::fields::curve25519_base_field,
                      basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_ed25519_range<BlueprintFieldType>::result_type
                generate_assignments(
                    const plonk_ed25519_range<BlueprintFieldType> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const typename plonk_ed25519_range<BlueprintFieldType>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;
                typename BlueprintFieldType::integral_type base = 1;
                std::array<typename BlueprintFieldType::integral_type, 4> ed25519_value = {
                    typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.input[0]).data),
                    typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.input[1]).data),
                    typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.input[2]).data),
                    typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.input[3]).data)};
                assignment.witness(component.W(0), row) = ed25519_value[0];
                assignment.witness(component.W(1), row) = ed25519_value[1];
                assignment.witness(component.W(2), row) = ed25519_value[2];
                assignment.witness(component.W(3), row) = ed25519_value[3];
                std::array<typename BlueprintFieldType::value_type, 12> range_chunks;
                typename BlueprintFieldType::integral_type mask = 0;
                typename BlueprintFieldType::value_type xi = 0;
                for (std::size_t i = 0; i < 4; i++) {
                    for (std::size_t j = 0; j < 3; j++) {
                        if (i == 3) {
                            if (j == 2) {
                                mask = (base << 15) - 1;
                                range_chunks[9 + j] = (ed25519_value[i] >> (21 * j)) & mask;
                                xi += range_chunks[i * 3 + j] - (base << 15) + 1;
                            } else {
                                mask = (base << 21) - 1;
                                range_chunks[9 + j] = (ed25519_value[i] >> (21 * j)) & mask;
                                xi += range_chunks[i * 3 + j] - (base << 21) + 1;
                            }
                        } else {
                            mask = (1 << 22) - 1;
                            range_chunks[i * 3 + j] = (ed25519_value[i] >> (22 * j)) & mask;
                            if (i + j != 0) {
                                xi += range_chunks[i * 3 + j] - (base << 22) + 1;
                            }
                        }
                    }
                }
                if (xi != 0) {
                    xi = xi.inversed();
                } else {
                    xi = 0;
                }
                assignment.witness(component.W(4), row) = range_chunks[0];
                assignment.witness(component.W(5), row) = range_chunks[1];
                assignment.witness(component.W(6), row) = range_chunks[2];
                assignment.witness(component.W(7), row) = range_chunks[3];
                assignment.witness(component.W(8), row) = xi;
                row++;
                assignment.witness(component.W(0), row) = range_chunks[4];
                assignment.witness(component.W(1), row) = range_chunks[5];
                assignment.witness(component.W(2), row) = range_chunks[6];
                assignment.witness(component.W(3), row) = range_chunks[7];
                assignment.witness(component.W(4), row) = range_chunks[8];
                assignment.witness(component.W(5), row) = range_chunks[9];
                assignment.witness(component.W(6), row) = range_chunks[10];
                assignment.witness(component.W(7), row) = range_chunks[11];
                bool c = 1;
                if (range_chunks[0] > (base << 22) - 20) {
                    c = 0;
                }
                assignment.witness(component.W(8), row) = c;
                return typename plonk_ed25519_range<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType>
            std::size_t generate_gates(
                const plonk_ed25519_range<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_ed25519_range<BlueprintFieldType>::input_type
                    &instance_input) {

                using var = typename plonk_ed25519_range<BlueprintFieldType>::var;

                typename BlueprintFieldType::integral_type base = 1;
                auto constraint_1 =
                    var(component.W(0), 0) - (var(component.W(4), 0) + var(component.W(5), 0) * (base << 22) +
                                              var(component.W(6), 0) * (base << 44));
                auto constraint_2 =
                    var(component.W(1), 0) - (var(component.W(7), 0) + var(component.W(0), +1) * (base << 22) +
                                              var(component.W(1), +1) * (base << 44));
                auto constraint_3 =
                    var(component.W(2), 0) - (var(component.W(2), +1) + var(component.W(3), +1) * (base << 22) +
                                              var(component.W(4), +1) * (base << 44));
                auto constraint_4 =
                    var(component.W(3), 0) - (var(component.W(5), +1) + var(component.W(6), +1) * (base << 21) +
                                              var(component.W(7), +1) * (base << 42));

                crypto3::zk::snark::plonk_constraint<BlueprintFieldType> sum =
                    var(component.W(5), 0) + var(component.W(6), 0) + var(component.W(7), 0) + var(component.W(0), +1) +
                    var(component.W(1), +1) + var(component.W(2), +1) + var(component.W(3), +1) +
                    var(component.W(4), +1) + var(component.W(5), +1) + var(component.W(6), +1) +
                    var(component.W(7), +1) - 2 * (base << 21) - 8 * (base << 22) - (base << 15) + 11;
                auto constraint_5 = sum * (var(component.W(8), 0) * sum - 1);
                auto constraint_6 =
                    var(component.W(8), 0) * sum + (1 - var(component.W(8), 0) * sum) * var(component.W(8), +1) - 1;

                return bp.add_gate({
                    constraint_1,
                    constraint_2,
                    constraint_3,
                    constraint_4,
                    constraint_5,
                    constraint_6,
                });
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_ed25519_range<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_ed25519_range<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_ed25519_range<BlueprintFieldType>::var;

                std::size_t row = start_row_index;
                if(var(component.W(0), static_cast<int>(row), false) != instance_input.input[0])
                    bp.add_copy_constraint({var(component.W(0), static_cast<int>(row), false), instance_input.input[0]});
                if(var(component.W(1), static_cast<int>(row), false) != instance_input.input[1])
                    bp.add_copy_constraint({var(component.W(1), static_cast<int>(row), false), instance_input.input[1]});
                if(var(component.W(2), static_cast<int>(row), false) != instance_input.input[2])
                    bp.add_copy_constraint({var(component.W(2), static_cast<int>(row), false), instance_input.input[2]});
                if(var(component.W(3), static_cast<int>(row), false) != instance_input.input[3])
                    bp.add_copy_constraint({var(component.W(3), static_cast<int>(row), false), instance_input.input[3]});
            }

            template<typename BlueprintFieldType>
            typename plonk_ed25519_range<BlueprintFieldType>::result_type generate_circuit(
                const plonk_ed25519_range<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_ed25519_range<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                std::size_t j = start_row_index;
                assignment.enable_selector(selector_index, j);
                generate_copy_constraints(component, bp, assignment, instance_input, j);
                return typename plonk_ed25519_range<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_REDUCTION_HPP
