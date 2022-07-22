//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/rpn_expression.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/verifier_index.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/binding.hpp>
using namespace nil::crypto3;

constexpr const std::size_t count_delimiters(const char *expression) {
    size_t i = 0;
    size_t cnt = 0;
    for (; expression[i] != '\0'; i++) {
        if (expression[i] == ';') {
            cnt++;
        }
    }
    return cnt;
}

constexpr const std::size_t str_len(const char *expression) {
    size_t size = 0;
    for (; expression[size] != '\0'; size++) {
    }
    return size;
}

constexpr std::size_t find_str(const char *expression, const char *str, std::size_t n, std::size_t start_pos,
                               std::size_t end_pos) {
    size_t j = 0;
    size_t i = start_pos;
    for (; i < end_pos; i++) {
        for (j = 0; j < n && expression[i + j] == str[j]; j++)
            ;
        if (j == n) {
            return i;
        }
    }
    return std::string::npos;
}

template<const std::size_t tokens_array_size, const std::size_t literal_string_size, typename ArithmetizationType,
         typename KimchiParamsType, std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4,
         std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
         std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
constexpr size_t rows(const char *expression) {
    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;
    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;

    using exponentiation_component = zk::components::exponentiation<ArithmetizationType, 64, W0, W1, W2, W3, W4, W5, W6,
                                                                    W7, W8, W9, W10, W11, W12, W13, W14>;

    const size_t mds_size = 3;
    std::array<std::size_t, tokens_array_size> str_start = {};

    std::array<std::size_t, tokens_array_size> str_end = {};
    str_start[0] = 0;
    str_end[tokens_array_size - 1] = literal_string_size;
    size_t i = 0;
    const char *alpha_c = "Alpha";
    const char *beta_c = "Beta";
    const char *gamma_c = "Gamma";
    const char *joint_combiner_c = "JointCombiner";
    const char *endo_coefficient_c = "EndoCoefficient";
    const char *mds_c = "Mds";
    const char *literal_c = "Literal";
    const char *cell_c = "Cell";
    const char *dup_c = "Dup";
    const char *pow_c = "Pow";
    const char *add_c = "Add";
    const char *mul_c = "Mul";
    const char *sub_c = "Sub";
    const char *vanishes_on_last_4_rows_c = "VanishesOnLast4Rows";
    const char *unnormalized_lagrange_basis_c = "UnnormalizedLagrangeBasis";
    const char *store_c = "Store";
    const char *load_c = "Load";
    const char *del = ";";
    for (i = 0; i < tokens_array_size - 1; i++) {
        size_t pos = find_str(expression, del, 1, str_start[i], literal_string_size);
        str_end[i] = pos;
        str_start[i + 1] = pos + 1;
    }
    size_t rows = 0;
    size_t constant_rows = 3 + mds_size * mds_size;
    for (i = 0; i < tokens_array_size; i++) {
        if (find_str(expression, literal_c, 7, str_start[i], str_end[i]) != std::string::npos) {
            constant_rows++;
        } else if (find_str(expression, pow_c, 3, str_start[i], str_end[i]) != std::string::npos) {
            rows += exponentiation_component::rows_amount;
            constant_rows++;
        } else if (find_str(expression, add_c, 3, str_start[i], str_end[i]) != std::string::npos) {
            rows += add_component::rows_amount;
        } else if (find_str(expression, mul_c, 3, str_start[i], str_end[i]) != std::string::npos) {
            rows += mul_component::rows_amount;
        } else if (find_str(expression, sub_c, 3, str_start[i], str_end[i]) != std::string::npos) {
            rows += sub_component::rows_amount;
        }
    }

    size_t res = std::max(rows, constant_rows);
    return res;
}