//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_UNIFIED_ADDITION_COMPONENT_11_WIRES_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_UNIFIED_ADDITION_COMPONENT_11_WIRES_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            // Input: P, Q - elliptic curve points
            // Output: R = P + Q
            template<typename ArithmetizationType, typename CurveType>
            class unified_addition;

            template<typename BlueprintFieldType, typename CurveType>
            class unified_addition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                CurveType>:
                public plonk_component<BlueprintFieldType> {

                static_assert(std::is_same<typename CurveType::base_field_type, BlueprintFieldType>::value);

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return unified_addition::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(11)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    return 1;
                }

                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                static constexpr const std::size_t gates_amount = 1;
                const std::string component_name = "native curve addition";

                struct input_type {
                    struct var_ec_point {
                        var x;
                        var y;
                    };

                    var_ec_point P;
                    var_ec_point Q;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {P.x, P.y, Q.x, Q.y};
                    }
                };

                struct result_type {
                    var X = var(0, 0, false);
                    var Y = var(0, 0, false);
                    result_type(const unified_addition &component, std::uint32_t start_row_index) {
                        X = var(component.W(4), start_row_index, false, var::column_type::witness);
                        Y = var(component.W(5), start_row_index, false, var::column_type::witness);
                    }

                    result_type() {
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {X, Y};
                    }
                };

                template <typename ContainerType>
                explicit unified_addition(ContainerType witness):
                    component_type(witness, {}, {}, get_manifest()){};

                template <typename WitnessContainerType, typename ConstantContainerType,
                    typename PublicInputContainerType>
                unified_addition(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input):
                    component_type(witness, constant, public_input, get_manifest()){};

                unified_addition(std::initializer_list<
                        typename component_type::witness_container_type::value_type> witnesses,
                               std::initializer_list<
                        typename component_type::constant_container_type::value_type> constants,
                               std::initializer_list<
                        typename component_type::public_input_container_type::value_type> public_inputs):
                    component_type(witnesses, constants, public_inputs, get_manifest()){};
            };

            template<typename BlueprintFieldType, typename CurveType>
            using plonk_native_unified_addition =
                unified_addition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, CurveType>;

            template<typename BlueprintFieldType, typename CurveType>
            typename plonk_native_unified_addition<BlueprintFieldType, CurveType>::result_type
                generate_assignments(
                    const plonk_native_unified_addition<BlueprintFieldType, CurveType> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                    const typename plonk_native_unified_addition<BlueprintFieldType, CurveType>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                const std::size_t j = start_row_index;

                typename BlueprintFieldType::value_type p_x = var_value(assignment, instance_input.P.x);
                typename BlueprintFieldType::value_type p_y = var_value(assignment, instance_input.P.y);
                typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type P(p_x,
                                                                                                         p_y);

                typename BlueprintFieldType::value_type q_x = var_value(assignment, instance_input.Q.x);
                typename BlueprintFieldType::value_type q_y = var_value(assignment, instance_input.Q.y);
                typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type Q(q_x,
                                                                                                         q_y);

                assignment.witness(component.W(0), j) = P.X;
                assignment.witness(component.W(1), j) = P.Y;
                assignment.witness(component.W(2), j) = Q.X;
                assignment.witness(component.W(3), j) = Q.Y;
                typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type zero = {
                    0u, 0u};
                if (P.X == zero.X && P.Y == zero.Y) {
                    assignment.witness(component.W(4), j) = Q.X;
                    assignment.witness(component.W(5), j) = Q.Y;
                } else {
                    if (Q.X == zero.X && Q.Y == zero.Y) {
                        assignment.witness(component.W(4), j) = P.X;
                        assignment.witness(component.W(5), j) = P.Y;
                    } else {
                        if (Q.X == P.X && Q.Y == -P.Y) {
                            assignment.witness(component.W(4), j) = 0u;
                            assignment.witness(component.W(5), j) = 0u;
                        } else {
                            assignment.witness(component.W(4), j) = (P + Q).X;
                            assignment.witness(component.W(5), j) = (P + Q).Y;
                        }
                    }
                }
                if (P.X != 0u) {
                    assignment.witness(component.W(6), j) = P.X.inversed();
                } else {
                    assignment.witness(component.W(6), j) = 0u;
                }

                if (Q.X != 0u) {
                    assignment.witness(component.W(7), j) = Q.X.inversed();
                } else {
                    assignment.witness(component.W(7), j) = 0u;
                }

                if (P.X != Q.X) {
                    assignment.witness(component.W(10), j) = (Q.Y - P.Y) * (Q.X - P.X).inversed();

                    assignment.witness(component.W(9), j) = 0u;

                    assignment.witness(component.W(8), j) = (Q.X - P.X).inversed();
                } else {

                    if (P.Y != -Q.Y) {
                        assignment.witness(component.W(9), j) = (Q.Y + P.Y).inversed();
                    } else {
                        assignment.witness(component.W(9), j) = 0u;
                    }
                    if (P.Y != 0u) {
                        assignment.witness(component.W(10), j) = (3u * (P.X * P.X)) * (2u * P.Y).inversed();
                    } else {
                        assignment.witness(component.W(10), j) = 0u;
                    }
                    assignment.witness(component.W(8), j) = 0u;
                }

                return typename plonk_native_unified_addition<BlueprintFieldType, CurveType>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename CurveType>
            std::size_t generate_gates(
                const plonk_native_unified_addition<BlueprintFieldType, CurveType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_native_unified_addition<BlueprintFieldType, CurveType>::input_type &instance_input) {

                using var =
                    typename plonk_native_unified_addition<BlueprintFieldType, CurveType>::var;

                auto constraint_1 =
                    (var(component.W(2), 0) - var(component.W(0), 0)) *
                    ((var(component.W(2), 0) - var(component.W(0), 0)) *
                     var(component.W(10), 0) - (var(component.W(3), 0) - var(component.W(1), 0)));
                auto constraint_2 =
                    (1u - (var(component.W(2), 0) - var(component.W(0), 0)) * var(component.W(8), 0)) *
                    (2u * var(component.W(1), 0) * var(component.W(10), 0) -
                     3u * var(component.W(0), 0) * var(component.W(0), 0));

                auto constraint_3 =
                    (var(component.W(0), 0) * var(component.W(2), 0) * var(component.W(2), 0) -
                     var(component.W(0), 0) * var(component.W(2), 0) * var(component.W(0), 0)) *
                    (var(component.W(10), 0) * var(component.W(10), 0) - var(component.W(0), 0) -
                     var(component.W(2), 0) - var(component.W(4), 0));
                auto constraint_4 =
                    (var(component.W(0), 0) * var(component.W(2), 0) * var(component.W(2), 0) -
                     var(component.W(0), 0) * var(component.W(2), 0) * var(component.W(0), 0)) *
                    (var(component.W(10), 0) * (var(component.W(0), 0) - var(component.W(4), 0)) -
                     var(component.W(1), 0) - var(component.W(5), 0));
                auto constraint_5 =
                    (var(component.W(0), 0) * var(component.W(2), 0) * var(component.W(3), 0) +
                     var(component.W(0), 0) * var(component.W(2), 0) * var(component.W(1), 0)) *
                    (var(component.W(10), 0) * var(component.W(10), 0) - var(component.W(0), 0) -
                     var(component.W(2), 0) - var(component.W(4), 0));
                auto constraint_6 =
                    (var(component.W(0), 0) * var(component.W(2), 0) * var(component.W(3), 0) +
                     var(component.W(0), 0) * var(component.W(2), 0) * var(component.W(1), 0)) *
                    (var(component.W(10), 0) * (var(component.W(0), 0) - var(component.W(4), 0)) -
                     var(component.W(1), 0) - var(component.W(5), 0));
                auto constraint_7 =
                    (1u - var(component.W(0), 0) * var(component.W(6), 0)) *
                        (var(component.W(4), 0) - var(component.W(2), 0));
                auto constraint_8 =
                    (1u - var(component.W(0), 0) * var(component.W(6), 0)) *
                        (var(component.W(5), 0) - var(component.W(3), 0));
                auto constraint_9 =
                    (1u - var(component.W(2), 0) * var(component.W(7), 0)) *
                        (var(component.W(4), 0) - var(component.W(0), 0));
                auto constraint_10 =
                    (1u - var(component.W(2), 0) * var(component.W(7), 0)) *
                        (var(component.W(5), 0) - var(component.W(1), 0));
                auto constraint_11 =
                    (1u - (var(component.W(2), 0) - var(component.W(0), 0)) * var(component.W(8), 0) -
                        (var(component.W(3), 0) + var(component.W(1), 0)) * var(component.W(9), 0)) *
                    var(component.W(4), 0);
                auto constraint_12 =
                    (1u - (var(component.W(2), 0) - var(component.W(0), 0)) * var(component.W(8), 0) -
                        (var(component.W(3), 0) + var(component.W(1), 0)) * var(component.W(9), 0)) *
                    var(component.W(5), 0);

                return bp.add_gate(
                    {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6,
                     constraint_7, constraint_8, constraint_9, constraint_10, constraint_11, constraint_12});
            }

            template<typename BlueprintFieldType, typename CurveType>
            void generate_copy_constraints(
                const plonk_native_unified_addition<BlueprintFieldType, CurveType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_native_unified_addition<BlueprintFieldType, CurveType>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_native_unified_addition<BlueprintFieldType, CurveType>::var;

                bp.add_copy_constraint({instance_input.P.x, var(component.W(0), start_row_index, false)});
                bp.add_copy_constraint({instance_input.P.y, var(component.W(1), start_row_index, false)});
                bp.add_copy_constraint({instance_input.Q.x, var(component.W(2), start_row_index, false)});
                bp.add_copy_constraint({instance_input.Q.y, var(component.W(3), start_row_index, false)});
            }

            template<typename BlueprintFieldType, typename CurveType>
            typename plonk_native_unified_addition<BlueprintFieldType, CurveType>::result_type
                generate_circuit(
                    const plonk_native_unified_addition<BlueprintFieldType, CurveType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                    const typename plonk_native_unified_addition<BlueprintFieldType, CurveType>::input_type &instance_input,
                    const std::size_t start_row_index){

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_native_unified_addition<BlueprintFieldType, CurveType>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_UNIFIED_ADDITION_COMPONENT_11_WIRES_HPP
