//---------------------------------------------------------------------------//
// Copyright (c) 2022-2023 Martun Karapetyan <martun@nil.foundation>
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
// @file Classes for mathematical expressions:
// - a term (i.e.,  a * x_i1 * x_i2 * ... * x_in)
// - an expression - stores any mathematical expression with -+* operatos and 'pow' in a form of a tree.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_MATH_EXPRESSION_HPP
#define CRYPTO3_ZK_MATH_EXPRESSION_HPP

#include <ostream>
#include <vector>
#include <unordered_map>
#include <functional>
#include <boost/functional/hash.hpp>
#include <boost/variant.hpp>
#include <boost/variant/recursive_wrapper.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {

            enum class ArithmeticOperator : std::uint8_t { ADD = 0, SUB = 1, MULT = 2 };

            /******************* Forward declarations of all the classes ******************/
            template<typename VariableType>
            class expression;

            template<typename VariableType>
            class term;

            template<typename VariableType>
            class pow_operation;

            template<typename VariableType>
            class binary_arithmetic_operation;

            /************** Definitions of all the classes **********************************/

            template<typename VariableType>
            class expression {
            public:
                // Theese typedefs are useful for usage in marshalling, for support of actor version.
                typedef VariableType variable_type;
                typedef term<variable_type> term_type;
                typedef pow_operation<variable_type> pow_operation_type;
                typedef binary_arithmetic_operation<variable_type> binary_arithmetic_operation_type;
                typedef typename variable_type::assignment_type assignment_type;

                // We intentionally don't add variable_type and assignment_type here,
                // They must be converted to term<VariableType> before being used.
                typedef boost::variant<boost::recursive_wrapper<term<variable_type>>,
                                       boost::recursive_wrapper<pow_operation<variable_type>>,
                                       boost::recursive_wrapper<binary_arithmetic_operation<variable_type>>>
                    expression_type;

                expression() : expr(term<variable_type>(assignment_type::zero())) {
                    update_hash();
                }

                expression(const term<variable_type>& expr) : expr(expr) {
                    update_hash();
                }
                expression(const pow_operation<variable_type>& expr) : expr(expr) {
                    update_hash();
                }
                expression(const binary_arithmetic_operation<variable_type>& expr) : expr(expr) {
                    update_hash();
                }
                expression(const variable_type& var) : expr(term<variable_type>(var)) {
                    update_hash();
                }

                // Every number type will be accepted here,
                // if it can be converted to 'assignment_type'.
                // This will include integral types and number<cpp_int_backend<...>>
                template<class NumberType>
                expression(const NumberType& coeff) : expr(term<variable_type>((assignment_type)coeff)) {
                    update_hash();
                }

                expression(const expression<variable_type>& other) = default;
                expression(expression<variable_type>&& other) = default;
                expression<variable_type>& operator=(const expression<variable_type>& other) = default;
                expression<variable_type>& operator=(expression<variable_type>&& other) = default;

                expression<variable_type> pow(const std::size_t power) const;
                expression<variable_type> operator-() const;

                // Operations between 2 expressions. Everything else is implicitly converted
                // to expression class.
                expression<variable_type>& operator+=(const expression<variable_type>& other);
                expression<variable_type>& operator-=(const expression<variable_type>& other);
                expression<variable_type>& operator*=(const expression<variable_type>& other);

                expression<variable_type> operator+(const expression<variable_type>& other) const;
                expression<variable_type> operator-(const expression<variable_type>& other) const;
                expression<variable_type> operator*(const expression<variable_type>& other) const;

                bool is_empty() const {
                    return *this == term<variable_type>(assignment_type::zero());
                }

                // Used for testing purposes. Checks for EXACT EQUALITY ONLY, no isomorphism!!!
                bool operator==(const expression<variable_type>& other) const;
                bool operator!=(const expression<variable_type>& other) const;

                const expression_type& get_expr() const {
                    return expr;
                }

                std::size_t get_hash() const {
                    return hash;
                }

                // This function must be called by all the non-const member functions
                // to make sure a fresh hash value is maintained.
                void update_hash() {
                    switch (expr.which()) {
                        case 0:
                            hash = boost::get<term<variable_type>>(expr).get_hash();
                            break;
                        case 1:
                            hash = boost::get<pow_operation<variable_type>>(expr).get_hash();
                            break;
                        case 2:
                            hash = boost::get<binary_arithmetic_operation<variable_type>>(expr).get_hash();
                            break;
                    }
                }

            private:
                // This is private, and we need to be very careful to make sure we recompute the hash value every time
                // this is changed through a non-const function.
                expression_type expr;

                // We will store the hash value. This is faster that computing it
                // whenever it's needed, because we need to iterate over subexpressions to compute it.
                std::size_t hash;
            };

            /**
             * A Non-Linear term represents a formal expression of the form
             * "coeff * w^{wire_index_1}_{rotation_1} * ... * w^{wire_index_k}_{rotation_k}", where
             * the values of w^{wire_index_1}_{rotation_1} can repeat.
             */
            template<typename VariableType>
            class term {
            public:
                typedef VariableType variable_type;
                typedef typename variable_type::assignment_type assignment_type;

                term() : coeff(assignment_type::zero()) {
                    update_hash();
                }

                term(const variable_type& var) : coeff(assignment_type::one()) {
                    vars.push_back(var);
                    update_hash();
                }

                // Every number type will be accepted here,
                // if it can be converted to 'assignment_type'.
                // This will include integral types and number<cpp_int_backend<...>>
                template<class NumberType>
                term(const NumberType& field_val) : coeff(field_val) {
                    update_hash();
                }

                term(const std::vector<variable_type>& vars, const assignment_type& coeff) : vars(vars), coeff(coeff) {
                    update_hash();
                }

                term(const std::vector<variable_type>& vars) : vars(vars), coeff(assignment_type::one()) {
                    update_hash();
                }

                term(const term<variable_type>& other) = default;
                term(term<variable_type>&& other) = default;
                term<variable_type>& operator=(const term<variable_type>& other) = default;
                term<variable_type>& operator=(term<variable_type>&& other) = default;

                bool is_zero() const {
                    return coeff == assignment_type::zero();
                }

                // This operator will also allow multiplication with VariableType and assignment_type
                // via an implicit conversion to term.
                term<variable_type> operator*(const term<variable_type>& other) const;
                expression<variable_type> operator+(const term<variable_type>& other) const;
                expression<variable_type> operator-(const term<variable_type>& other) const;

                expression<variable_type> pow(const std::size_t power) const;
                term operator-() const;

                bool operator==(const term<variable_type>& other) const;
                bool operator!=(const term<variable_type>& other) const;

                // Used for debugging, to be able to see what's inside the term.
                std::string to_string() const;

                // If variables repeat, in some cases we
                // want to be able to represent it as Product(var_i^power_i).
                std::unordered_map<variable_type, int> to_unordered_map() const;

                std::size_t get_hash() const {
                    return hash;
                }

                void update_hash() {
                    std::hash<variable_type> vars_hasher;
                    std::hash<typename variable_type::assignment_type> coeff_hasher;

                    std::size_t result = coeff_hasher(coeff);
                    auto vars_sorted = vars;
                    sort(vars_sorted.begin(), vars_sorted.end());
                    for (const auto& var : vars_sorted) {
                        boost::hash_combine(result, vars_hasher(var));
                    }
                    hash = result;
                }

                const std::vector<variable_type>& get_vars() const {
                    return vars;
                }

                const assignment_type& get_coeff() const {
                    return coeff;
                }

            private:
                // This is private, and we need to be very careful to make sure we recompute the hash value every time
                // this is changed through a non-const function.
                std::vector<variable_type> vars;
                assignment_type coeff;

                // We will store the hash value. This is faster that computing it
                // whenever it's needed, because we need to iterate over subexpressions to compute it.
                std::size_t hash;
            };

            template<typename VariableType>
            class pow_operation {
            public:
                typedef VariableType variable_type;

                pow_operation(const expression<variable_type>& expr, int power) : expr(expr), power(power) {
                    update_hash();
                }

                pow_operation(const pow_operation<variable_type>& other) = default;
                pow_operation(pow_operation<variable_type>&& other) = default;
                pow_operation<variable_type>& operator=(const pow_operation<variable_type>& other) = default;
                pow_operation<variable_type>& operator=(pow_operation<variable_type>&& other) = default;

                // Used for testing purposes, and hashmaps. Checks for EXACT EQUALITY ONLY, no isomorphism!!!
                bool operator==(const pow_operation<variable_type>& other) const;
                bool operator!=(const pow_operation<variable_type>& other) const;

                const expression<variable_type>& get_expr() const {
                    return expr;
                }

                int get_power() const {
                    return power;
                }

                std::size_t get_hash() const {
                    return hash;
                }

                void update_hash() {
                    std::size_t result = expr.get_hash();
                    boost::hash_combine(result, power);
                    hash = result;
                }

            private:
                // This is private, and we need to be very careful to make sure we recompute the hash value every time
                // this is changed through a non-const function.
                expression<variable_type> expr;
                int power;

                // We will store the hash value. This is faster that computing it
                // whenever it's needed, because we need to iterate over subexpressions to compute it.
                std::size_t hash;
            };

            // One of +, -, *, / operations. We build an expression tree using this class.
            template<typename variable_type>
            class binary_arithmetic_operation {
            public:
                using arithmetic_operator_type = ArithmeticOperator;

                binary_arithmetic_operation(const expression<variable_type>& expr_left,
                                            const expression<variable_type>& expr_right,
                                            arithmetic_operator_type op) :
                    expr_left(expr_left), expr_right(expr_right), op(op) {
                    update_hash();
                }

                binary_arithmetic_operation(const binary_arithmetic_operation<variable_type>& other) = default;
                binary_arithmetic_operation(binary_arithmetic_operation<variable_type>&& other) = default;
                binary_arithmetic_operation<variable_type>&
                    operator=(const binary_arithmetic_operation<variable_type>& other) = default;
                binary_arithmetic_operation<variable_type>&
                    operator=(binary_arithmetic_operation<variable_type>&& other) = default;

                // Used for testing purposes and hashmaps. Checks for EXACT EQUALITY ONLY, no isomorphism!!!
                bool operator==(const binary_arithmetic_operation<variable_type>& other) const;
                bool operator!=(const binary_arithmetic_operation<variable_type>& other) const;

                // Use for testing.
                std::string get_operator_string() const {
                    switch (op) {
                        case arithmetic_operator_type::ADD:
                            return "+";
                        case arithmetic_operator_type::SUB:
                            return "-";
                        case arithmetic_operator_type::MULT:
                            return "*";
                        default:
                            __builtin_unreachable();
                    }
                }

                const expression<variable_type>& get_expr_left() const {
                    return expr_left;
                }

                const expression<variable_type>& get_expr_right() const {
                    return expr_right;
                }

                const ArithmeticOperator& get_op() const {
                    return op;
                }

                std::size_t get_hash() const {
                    return hash;
                }

                void update_hash() {
                    std::size_t result = expr_left.get_hash();
                    boost::hash_combine(result, expr_right.get_hash());
                    boost::hash_combine(result, (std::size_t)op);
                    hash = result;
                }

            private:
                // This is private, and we need to be very careful to make sure we recompute the hash value every time
                // this is changed through a non-const function.
                expression<variable_type> expr_left;
                expression<variable_type> expr_right;
                arithmetic_operator_type op;

                // We will store the hash value. This is faster that computing it
                // whenever it's needed, because we need to iterate over subexpressions to compute it.
                std::size_t hash;
            };

            /*********** Member function bodies for class 'term' *******************************/
            template<typename variable_type>
            term<variable_type> term<variable_type>::operator*(const term<variable_type>& other) const {
                if (this->is_zero() || other.is_zero())
                    return term<variable_type>();

                term<variable_type> result(this->vars);
                std::copy(other.vars.begin(), other.vars.end(), std::back_inserter(result.vars));
                result.coeff = other.coeff * this->coeff;
                result.update_hash();
                return result;
            }

            template<typename variable_type>
            expression<variable_type> term<variable_type>::operator+(const term<variable_type>& other) const {

                return expression<variable_type>(*this) + other;
            }

            template<typename variable_type>
            expression<variable_type> term<variable_type>::operator-(const term<variable_type>& other) const {
                return expression<variable_type>(*this) - other;
            }

            template<typename variable_type>
            expression<variable_type> term<variable_type>::pow(const std::size_t power) const {
                return pow_operation<variable_type>(*this, power);
            }

            template<typename variable_type>
            term<variable_type> term<variable_type>::operator-() const {
                return term<variable_type>(this->vars, -this->coeff);
            }

            /*********** Member function bodies for class 'expression' *******************************/

            template<typename variable_type>
            expression<variable_type> expression<variable_type>::pow(const std::size_t power) const {
                return pow_operation<variable_type>(*this, power);
            }

            template<typename variable_type>
            expression<variable_type> expression<variable_type>::operator-() const {
                return term<variable_type>(assignment_type::zero()) - (*this);
            }

            template<typename variable_type>
            expression<variable_type>& expression<variable_type>::operator+=(const expression<variable_type>& other) {
                if (this->is_empty())
                    *this = other;
                else if (!other.is_empty()) {
                    expr = binary_arithmetic_operation<variable_type>(*this, other, ArithmeticOperator::ADD);
                }
                update_hash();
                return *this;
            }

            template<typename variable_type>
            expression<variable_type>& expression<variable_type>::operator-=(const expression<variable_type>& other) {
                expr = binary_arithmetic_operation<variable_type>(*this, other, ArithmeticOperator::SUB);
                update_hash();
                return *this;
            }

            template<typename variable_type>
            expression<variable_type>& expression<variable_type>::operator*=(const expression<variable_type>& other) {
                if (this->is_empty() || other.is_empty()) {
                    *this = expression<variable_type>();
                } else {
                    expr = binary_arithmetic_operation<variable_type>(*this, other, ArithmeticOperator::MULT);
                }
                update_hash();
                return *this;
            }

            template<typename variable_type>
            expression<variable_type>
                expression<variable_type>::operator+(const expression<variable_type>& other) const {
                if (this->is_empty())
                    return other;
                if (other.is_empty())
                    return *this;
                return binary_arithmetic_operation<variable_type>(*this, other, ArithmeticOperator::ADD);
            }

            template<typename variable_type>
            expression<variable_type>
                expression<variable_type>::operator-(const expression<variable_type>& other) const {
                return binary_arithmetic_operation<variable_type>(*this, other, ArithmeticOperator::SUB);
            }

            template<typename variable_type>
            expression<variable_type>
                expression<variable_type>::operator*(const expression<variable_type>& other) const {
                if (this->is_empty() || other.is_empty())
                    return expression<variable_type>();

                return binary_arithmetic_operation<variable_type>(*this, other, ArithmeticOperator::MULT);
            }

            /***** Operators for [VariableType or assignment_type or int] +-* term. **********************/
            template<
                typename variable_type,
                typename LeftType,
                typename = std::enable_if_t<std::is_same<LeftType, variable_type>::value ||
                                            std::is_same<LeftType, typename variable_type::assignment_type>::value ||
                                            std::is_integral<LeftType>::value>>
            term<variable_type> operator*(const LeftType& left, const term<variable_type>& t) {
                return term<variable_type>(left) * t;
            }

            template<
                typename variable_type,
                typename LeftType,
                typename = std::enable_if_t<std::is_same<LeftType, variable_type>::value ||
                                            std::is_same<LeftType, typename variable_type::assignment_type>::value ||
                                            std::is_integral<LeftType>::value>>
            expression<variable_type> operator+(const LeftType& left, const term<variable_type>& t) {
                return term<variable_type>(left) + t;
            }

            template<
                typename variable_type,
                typename LeftType,
                typename = std::enable_if_t<std::is_same<LeftType, variable_type>::value ||
                                            std::is_same<LeftType, typename variable_type::assignment_type>::value ||
                                            std::is_integral<LeftType>::value>>
            expression<variable_type> operator-(const LeftType& left, const term<variable_type>& t) {
                return term<variable_type>(left) - t;
            }

            // Operators for [VariableType or assignment_type or int] +-* expression.
            template<typename variable_type,
                     typename LeftType,
                     typename = std::enable_if_t<
                         std::is_same<LeftType, variable_type>::value ||
                         std::is_same<LeftType, typename variable_type::assignment_type>::value ||
                         std::is_same<LeftType, term<variable_type>>::value || std::is_integral<LeftType>::value>>
            expression<variable_type> operator*(const LeftType& left, const expression<variable_type>& exp) {
                return expression<variable_type>(left) * exp;
            }

            template<typename variable_type,
                     typename LeftType,
                     typename = std::enable_if_t<
                         std::is_same<LeftType, variable_type>::value ||
                         std::is_same<LeftType, typename variable_type::assignment_type>::value ||
                         std::is_same<LeftType, term<variable_type>>::value || std::is_integral<LeftType>::value>>
            expression<variable_type> operator+(const LeftType& left, const expression<variable_type>& exp) {
                return expression<variable_type>(left) + exp;
            }

            template<typename variable_type,
                     typename LeftType,
                     typename = std::enable_if_t<
                         std::is_same<LeftType, variable_type>::value ||
                         std::is_same<LeftType, typename variable_type::assignment_type>::value ||
                         std::is_same<LeftType, term<variable_type>>::value || std::is_integral<LeftType>::value>>
            expression<variable_type> operator-(const LeftType& left, const expression<variable_type>& exp) {
                return expression<variable_type>(left) - exp;
            }

            template<typename variable_type>
            std::unordered_map<variable_type, int> term<variable_type>::to_unordered_map() const {
                std::unordered_map<variable_type, int> vars_map;
                for (const auto& var : vars) {
                    auto iter = vars_map.find(var);
                    if (iter != vars_map.end()) {
                        iter->second++;
                    } else {
                        vars_map[var] = 1;
                    }
                }
                return vars_map;
            }

            template<typename variable_type>
            bool term<variable_type>::operator==(const term<variable_type>& other) const {
                if (this->coeff != other.coeff) {
                    return false;
                }
                if (this->vars.size() != other.vars.size()) {
                    return false;
                }
                // Put both vars and other->vars into a hashmap, and check if
                // everything is equal.
                auto vars_map = this->to_unordered_map();
                for (const auto& var : other.vars) {
                    auto iter = vars_map.find(var);
                    if (iter != vars_map.end()) {
                        iter->second--;
                    } else {
                        return false;
                    }
                }
                for (const auto& entry : vars_map) {
                    if (entry.second != 0)
                        return false;
                }
                return true;
            }

            // Used for testing purposes and hashmaps.
            template<typename variable_type>
            bool term<variable_type>::operator!=(const term<variable_type>& other) const {
                return !(*this == other);
            }

            template<typename variable_type>
            void print_coefficient(std::ostream& os, const term<variable_type>& term) {
                if (term.get_coeff() == -variable_type::assignment_type::one())
                    os << "(-1)";
                else
                    os << term.get_coeff();
            }

            // Used in the unit tests, so we can use BOOST_CHECK_EQUALS, and see
            // the values of terms, when the check fails.
            template<typename variable_type>
            std::ostream& operator<<(std::ostream& os, const term<variable_type>& term) {
                if (!term.get_coeff().is_one()) {
                    print_coefficient(os, term);
                    if (term.get_vars().size() != 0) {
                        os << " * ";
                    }
                } else if (term.get_vars().size() == 0) {
                    print_coefficient(os, term);
                }
                bool first = true;
                for (const auto& var : term.get_vars()) {
                    if (!first)
                        os << " * ";
                    os << var;
                    first = false;
                }
                return os;
            }

            // Used in the unit tests, so we can use BOOST_CHECK_EQUALS, and see
            // the values of terms, when the check fails.
            template<typename variable_type>
            std::ostream& operator<<(std::ostream& os, const pow_operation<variable_type>& power) {
                os << "(" << power.get_expr() << " ^ " << power.get_power() << ")";
                return os;
            }

            // Used in the unit tests, so we can use BOOST_CHECK_EQUALS, and see
            // the values of terms, when the check fails.
            template<typename variable_type>
            std::ostream& operator<<(std::ostream& os, const binary_arithmetic_operation<variable_type>& bin_op) {
                os << "(" << bin_op.get_expr_left() << " " << bin_op.get_operator_string() << " "
                   << bin_op.get_expr_right() << ")";
                return os;
            }

            // Used in the unit tests, so we can use BOOST_CHECK_EQUALS, and see
            // the values of terms, when the check fails.
            template<typename variable_type>
            std::ostream& operator<<(std::ostream& os, const expression<variable_type>& expr) {
                os << expr.get_expr();
                return os;
            }

            // Used for testing purposes and hashmaps. Checks for EXACT EQUALITY ONLY, no isomorphism!!!
            template<typename variable_type>
            bool pow_operation<variable_type>::operator==(const pow_operation<variable_type>& other) const {
                return this->power == other.get_power() && this->expr == other.get_expr();
            }

            // Used for testing purposes.
            template<typename variable_type>
            bool pow_operation<variable_type>::operator!=(const pow_operation<variable_type>& other) const {
                return !(*this == other);
            }

            // Used for testing purposes and hashmaps. Checks for EXACT EQUALITY ONLY, no isomorphism!!!
            template<typename variable_type>
            bool binary_arithmetic_operation<variable_type>::operator==(
                const binary_arithmetic_operation<variable_type>& other) const {
                return this->op == other.get_op() && this->expr_left == other.get_expr_left() &&
                       this->expr_right == other.get_expr_right();
            }

            // Used for testing purposes. Checks for EXACT EQUALITY ONLY, no isomorphism!!!
            template<typename variable_type>
            bool binary_arithmetic_operation<variable_type>::operator!=(
                const binary_arithmetic_operation<variable_type>& other) const {
                return !(*this == other);
            }

            // Used for testing purposes and hashmaps. Checks for EXACT EQUALITY ONLY, no isomorphism!!!
            template<typename variable_type>
            bool expression<variable_type>::operator==(const expression<variable_type>& other) const {
                return this->expr == other.get_expr();
            }

            // Used for testing purposes and hashmaps. Checks for EXACT EQUALITY ONLY, no isomorphism!!!
            template<typename variable_type>
            bool expression<variable_type>::operator!=(const expression<variable_type>& other) const {
                return this->expr != other.get_expr();
            }
        }    // namespace math
    }    // namespace crypto3
}    // namespace nil

template<typename variable_type>
struct std::hash<nil::crypto3::math::term<variable_type>> {
    std::size_t operator()(const nil::crypto3::math::term<variable_type>& term) const {
        // Hash is always pre-computed and store in the term itself.
        return term.get_hash();
    }
};

template<typename variable_type>
struct std::hash<nil::crypto3::math::expression<variable_type>> {
    std::size_t operator()(const nil::crypto3::math::expression<variable_type>& expr) const {
        // Hash is always pre-computed and store in the expression itself.
        return expr.get_hash();
    }
};

#endif    // CRYPTO3_ZK_MATH_EXPRESSION_HPP
