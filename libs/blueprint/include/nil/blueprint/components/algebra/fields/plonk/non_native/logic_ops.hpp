//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_FIELDS_logic_OPS_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_FIELDS_logic_OPS_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/boolean_op_component.hpp>

using nil::blueprint::components::detail::boolean_op_component;

namespace nil {
    namespace blueprint {
        namespace components {

            /*
                The following logical operations do NOT perform any checks on the input values.
            */

            template<typename ArithmetizationType>
            class logic_not;

            template<typename BlueprintFieldType>
            class logic_not<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                             : public boolean_op_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType>,
                                                           1> {

                using value_type = typename BlueprintFieldType::value_type;

            public:
                using component_type =
                    boolean_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, 1>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return logic_not::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    return component_type::get_manifest();
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    return component_type::get_rows_amount(witness_amount);
                }
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                const std::string component_name = "logic_not";

                virtual crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
                        op_constraint(const std::array<var, 2> &witnesses) const {
                    return 1 - witnesses[0] - witnesses[1];
                }

                virtual value_type result_assignment(const std::array<value_type, 1> &input_values) const {
                    return 1 - input_values[0];
                }

                template<typename ContainerType>
                explicit logic_not(ContainerType witness) : component_type(witness, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_not(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                logic_not(std::initializer_list<typename component_type::witness_container_type::value_type>
                               witnesses,
                           std::initializer_list<typename component_type::constant_container_type::value_type>
                               constants,
                           std::initializer_list<typename component_type::public_input_container_type::value_type>
                               public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };


            template<typename ArithmetizationType>
            class logic_and;

            template<typename BlueprintFieldType>
            class logic_and<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                             : public boolean_op_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType>,
                                                           2> {

                using value_type = typename BlueprintFieldType::value_type;

            public:
                using component_type =
                    boolean_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, 2>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return logic_and::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    return component_type::get_manifest();
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    return component_type::get_rows_amount(witness_amount);
                }
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                const std::string component_name = "logic_and";

                virtual crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
                        op_constraint(const std::array<var, 3> &witnesses) const {
                    return witnesses[2] - witnesses[0] * witnesses[1];
                }

                virtual value_type result_assignment(const std::array<value_type, 2> &input_values) const {
                    return input_values[0] * input_values[1];
                }

                template<typename ContainerType>
                explicit logic_and(ContainerType witness) : component_type(witness, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_and(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                logic_and(std::initializer_list<typename component_type::witness_container_type::value_type>
                               witnesses,
                           std::initializer_list<typename component_type::constant_container_type::value_type>
                               constants,
                           std::initializer_list<typename component_type::public_input_container_type::value_type>
                               public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };


            template<typename ArithmetizationType>
            class logic_or;

            template<typename BlueprintFieldType>
            class logic_or<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                            : public boolean_op_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType>, 2>
            {

                using value_type = typename BlueprintFieldType::value_type;

            public:
                using component_type =
                    boolean_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, 2>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return logic_or::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    return component_type::get_manifest();
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    return component_type::get_rows_amount(witness_amount);
                }
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                const std::string component_name = "logic_or";

                virtual crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
                        op_constraint(const std::array<var, 3> &witnesses) const {
                    return witnesses[2] - (witnesses[0] + witnesses[1] - witnesses[0] * witnesses[1]);
                }

                virtual value_type result_assignment(const std::array<value_type, 2> &input_values) const {
                    return input_values[0] + input_values[1] - input_values[0] * input_values[1];
                }

                template<typename ContainerType>
                explicit logic_or(ContainerType witness) : component_type(witness, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_or(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                logic_or(std::initializer_list<typename component_type::witness_container_type::value_type>
                               witnesses,
                           std::initializer_list<typename component_type::constant_container_type::value_type>
                               constants,
                           std::initializer_list<typename component_type::public_input_container_type::value_type>
                               public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };


            template<typename ArithmetizationType>
            class logic_xor;

            template<typename BlueprintFieldType>
            class logic_xor<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                             : public boolean_op_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType>, 2>
            {

                using value_type = typename BlueprintFieldType::value_type;

            public:
                using component_type =
                    boolean_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, 2>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return logic_xor::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    return component_type::get_manifest();
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    return component_type::get_rows_amount(witness_amount);
                }
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                const std::string component_name = "logic_xor";

                virtual crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
                        op_constraint(const std::array<var, 3> &witnesses) const {
                    return witnesses[2] - (witnesses[0] + witnesses[1] - 2 * witnesses[0] * witnesses[1]);
                }

                virtual value_type result_assignment(const std::array<value_type, 2> &input_values) const {
                    return input_values[0] + input_values[1] - 2 * input_values[0] * input_values[1];
                }

                template<typename ContainerType>
                explicit logic_xor(ContainerType witness) : component_type(witness, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_xor(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                logic_xor(std::initializer_list<typename component_type::witness_container_type::value_type>
                                witnesses,
                            std::initializer_list<typename component_type::constant_container_type::value_type>
                                constants,
                            std::initializer_list<typename component_type::public_input_container_type::value_type>
                                public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };


            template<typename ArithmetizationType>
            class logic_nand;

            template<typename BlueprintFieldType>
            class logic_nand<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                             : public boolean_op_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType>, 2>
            {

                constexpr static const std::uint32_t WitnessesAmount = 3;

                using value_type = typename BlueprintFieldType::value_type;

            public:
                using component_type =
                    boolean_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, 2>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return logic_nand::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    return component_type::get_manifest();
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    return component_type::get_rows_amount(witness_amount);
                }
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                const std::string component_name = "logic_nand";

                virtual crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
                        op_constraint(const std::array<var, 3> &witnesses) const {
                    return witnesses[2] - (1 - witnesses[0] * witnesses[1]);
                }

                virtual value_type result_assignment(const std::array<value_type, 2> &input_values) const {
                    return 1 - input_values[0] * input_values[1];
                }

                template<typename ContainerType>
                explicit logic_nand(ContainerType witness) : component_type(witness, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_nand(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                logic_nand(std::initializer_list<typename component_type::witness_container_type::value_type>
                                witnesses,
                           std::initializer_list<typename component_type::constant_container_type::value_type>
                                constants,
                           std::initializer_list<typename component_type::public_input_container_type::value_type>
                                public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename ArithmetizationType>
            class logic_nor;

            template<typename BlueprintFieldType>
            class logic_nor<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                             : public boolean_op_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType>, 2>
            {

                using value_type = typename BlueprintFieldType::value_type;

            public:
                using component_type =
                    boolean_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, 2>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return logic_nor::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    return component_type::get_manifest();
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    return component_type::get_rows_amount(witness_amount);
                }
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                const std::string component_name = "logic_nor";

                virtual crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
                        op_constraint(const std::array<var, 3> &witnesses) const {
                    return witnesses[2] - (1 - (witnesses[0] + witnesses[1] - witnesses[0] * witnesses[1]));
                }

                virtual value_type result_assignment(const std::array<value_type, 2> &input_values) const {
                    return 1 - (input_values[0] + input_values[1] - input_values[0] * input_values[1]);
                }

                template<typename ContainerType>
                explicit logic_nor(ContainerType witness) : component_type(witness, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_nor(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                logic_nor(std::initializer_list<typename component_type::witness_container_type::value_type>
                                witnesses,
                          std::initializer_list<typename component_type::constant_container_type::value_type>
                                constants,
                          std::initializer_list<typename component_type::public_input_container_type::value_type>
                                public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            // if (cond) then (a) else (b)
            // expects cond to be a boolean
            template<typename ArithmetizationType>
            class select;

            template<typename BlueprintFieldType>
            class select<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                             : public boolean_op_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType>,
                                                           3> {

                using value_type = typename BlueprintFieldType::value_type;

            public:
                using component_type =
                    boolean_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, 3>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return select::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    return component_type::get_manifest();
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    return component_type::get_rows_amount(witness_amount);
                }

                virtual crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
                        op_constraint(const std::array<var, 4> &witnesses) const {
                    return witnesses[3] - (witnesses[0] * witnesses[1] + (1 - witnesses[0]) * witnesses[2]);
                }

                virtual value_type result_assignment(const std::array<value_type, 3> &input_values) const {
                    return input_values[0] == 0 ? input_values[2] : input_values[1];
                }

                template<typename ContainerType>
                explicit select(ContainerType witness) : component_type(witness, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                select(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                select(std::initializer_list<typename component_type::witness_container_type::value_type>
                                witnesses,
                          std::initializer_list<typename component_type::constant_container_type::value_type>
                                constants,
                          std::initializer_list<typename component_type::public_input_container_type::value_type>
                                public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_FIELDS_logic_OPS_HPP
