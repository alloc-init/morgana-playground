//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>
//  Copyright (c) 2021-2022 Aleksei Moskvin <alalmoskvin@gmail.com>
//  Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MERKLE_PROOF_HPP
#define CRYPTO3_MERKLE_PROOF_HPP

#include <algorithm>
#include <vector>
#include <stack>

#include <boost/variant.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                template<typename, typename, std::size_t>
                struct merkle_proof;
            }    // namespace components
        }        // namespace zk
        namespace marshalling {
            namespace types {
                template<typename, typename>
                struct merkle_proof_marshalling;
            }
        }    // namespace marshalling
        namespace containers {
            namespace detail {
                template<typename NodeType, std::size_t Arity = 2>
                struct merkle_proof_impl {
                    typedef NodeType node_type;
                    typedef typename node_type::hash_type hash_type;

                    constexpr static const std::size_t arity = Arity;

                    constexpr static const std::size_t value_bits = node_type::value_bits;
                    typedef typename node_type::value_type value_type;

                    struct path_element_type {
                        path_element_type(value_type x, size_t pos) : _hash(x), _position(pos) {
                        }
                        path_element_type() {
                        }

                        bool operator==(const path_element_type &rhs) const {
                            return _hash == rhs._hash && _position == rhs._position;
                        }
                        bool operator!=(const path_element_type &rhs) const {
                            return !(rhs == *this);
                        }

                        const value_type &hash() const {
                            return _hash;
                        }

                        std::size_t position() const {
                            return _position;
                        }

                        value_type _hash;
                        std::size_t _position;

                        template<typename, typename>
                        friend class nil::crypto3::marshalling::types::merkle_proof_marshalling;
                    };

                    typedef std::array<path_element_type, Arity - 1> layer_type;
                    typedef std::vector<layer_type> path_type;

                    merkle_proof_impl() : _li(0) {};

                    merkle_proof_impl(std::size_t li, value_type root, path_type path) : _li(li), _root(root),
                                                                                         _path(path){};

                    merkle_proof_impl(const merkle_tree<hash_type, arity> &tree, const std::size_t leaf_idx) {
                        _root = tree.root();
                        _path.resize(tree.row_count() - 1);
                        _li = leaf_idx;

                        typename std::vector<layer_type>::iterator v_itr = _path.begin();
                        std::size_t cur_leaf = leaf_idx;
                        std::size_t row_len = tree.leaves();
                        std::size_t row_begin_idx = 0;
                        while (cur_leaf != tree.size() - 1) {    // while it's not _root
                            std::size_t cur_leaf_pos = cur_leaf % arity;
                            std::size_t cur_leaf_arity_pos = (cur_leaf - row_begin_idx) / arity;
                            std::size_t begin_this_arity = cur_leaf - cur_leaf_pos;
                            typename layer_type::iterator a_itr = v_itr->begin();
                            for (size_t i = 0; i < cur_leaf_pos; ++i, ++begin_this_arity, ++a_itr) {
                                *a_itr = path_element_type(tree[begin_this_arity], i);
                            }
                            for (size_t i = cur_leaf_pos + 1; i < arity; ++i, ++begin_this_arity, ++a_itr) {
                                *a_itr = path_element_type(tree[begin_this_arity + 1], i);
                            }
                            v_itr++;
                            cur_leaf = row_len + row_begin_idx + cur_leaf_arity_pos;
                            row_begin_idx += row_len;
                            row_len /= arity;
                        }
                    }

                    template<typename Hashable>
                    bool validate(const Hashable &a) const {
                        value_type d = crypto3::hash<hash_type>(a);
                        for (auto &it : _path) {
                            accumulator_set<hash_type> acc;
                            size_t i = 0;
                            for (; (i < arity - 1) && i == it[i]._position; ++i) {
                                crypto3::hash<hash_type>(it[i]._hash.begin(), it[i]._hash.end(), acc);
                            }
                            crypto3::hash<hash_type>(d.begin(), d.end(), acc);
                            for (; i < arity - 1; ++i) {
                                crypto3::hash<hash_type>(it[i]._hash.begin(), it[i]._hash.end(), acc);
                            }
                            d = accumulators::extract::hash<hash_type>(acc);
                        }
                        return (d == _root);
                    }

                    std::size_t leaf_index() const {
                        return _li;
                    }

                    bool operator==(const merkle_proof_impl &rhs) const {
                        return _li == rhs._li && _root == rhs._root && _path == rhs._path;
                    }
                    bool operator!=(const merkle_proof_impl &rhs) const {
                        return !(rhs == *this);
                    }

                    const value_type &root() const {
                        return _root;
                    }

                    const path_type &path() const {
                        return _path;
                    }

                private:
                    std::size_t _li;
                    value_type _root;
                    path_type _path;

                    template<typename, typename, std::size_t>
                    friend class nil::crypto3::zk::components::merkle_proof;

                    template<typename, typename>
                    friend class nil::crypto3::marshalling::types::merkle_proof_marshalling;

                    template<typename, std::size_t>
                    friend std::vector<merkle_proof_impl<NodeType, Arity>> 
                        generate_compressed_proofs(const merkle_tree<hash_type, arity> &tree, 
                                                    const std::vector<std::size_t> leaf_idxs);

                    template<typename Hashable, typename, std::size_t>
                    friend bool validate_compressed_proofs(const std::vector<merkle_proof_impl<NodeType, Arity>> &proofs,
                                                            const std::vector<Hashable> &a_vec);
                };
            }    // namespace detail
            
            template<typename T, std::size_t Arity>
            std::vector<detail::merkle_proof_impl<detail::merkle_tree_node<T>, Arity>> 
                generate_compressed_proofs(const containers::merkle_tree<typename detail::merkle_tree_node<T>::hash_type, Arity> &tree, 
                                            std::vector<std::size_t> leaf_idxs) {
                assert(leaf_idxs.size() > 0);
                std::sort(leaf_idxs.begin(), leaf_idxs.end());
                typedef typename detail::merkle_tree_node<T> NodeType;
                typedef typename detail::merkle_proof_impl<NodeType, Arity>::path_element_type path_element_type;
                typedef std::array<path_element_type, Arity - 1> layer_type;
                std::vector<detail::merkle_proof_impl<NodeType, Arity>> proofs;
                proofs.reserve(leaf_idxs.size());
                std::size_t row_len = tree.leaves();
                std::vector<bool> known(2 * row_len, false);
                for (auto leaf_idx : leaf_idxs) {
                    std::vector<layer_type> path(tree.row_count() - 1);
                    typename std::vector<layer_type>::iterator v_itr = path.begin();
                    std::size_t cur_leaf = leaf_idx;
                    std::size_t row_len = tree.leaves();
                    std::size_t row_begin_idx = 0;
                    bool finish_path = false;
                    bool all_known = true;
                    while (cur_leaf != tree.size() - 1) {
                        std::size_t cur_leaf_pos = cur_leaf % Arity;
                        std::size_t cur_leaf_arity_pos = (cur_leaf - row_begin_idx) / Arity;
                        std::size_t begin_this_arity = cur_leaf - cur_leaf_pos;
                        typename layer_type::iterator a_itr = v_itr->begin();
                        for (size_t i = 0; i < cur_leaf_pos; ++i, ++begin_this_arity) {
                            if (!known[begin_this_arity + i]) {
                                known[begin_this_arity + i] = true;
                                all_known = false;
                            } else {
                                finish_path = true;
                            }
                            *a_itr = path_element_type(tree[begin_this_arity], i);
                            ++a_itr;
                        }
                        for (size_t i = cur_leaf_pos + 1; i < Arity; ++i, ++begin_this_arity) {
                            if (!known[begin_this_arity + 1]) {
                                known[begin_this_arity + 1] = true;
                                all_known = false;
                            } else {
                                finish_path = true;
                            }
                            *a_itr = path_element_type(tree[begin_this_arity + 1], i);
                            ++a_itr;
                        }
                        if (all_known == true && v_itr - path.begin() > 0) {
                            break;
                        }
                        v_itr++;
                        if (finish_path) {
                            break;
                        }
                        cur_leaf = row_len + row_begin_idx + cur_leaf_arity_pos;
                        row_begin_idx += row_len;
                        row_len /= Arity;
                    }
                    path.resize(v_itr - path.begin());
                    proofs.push_back(detail::merkle_proof_impl<NodeType, Arity>(leaf_idx, tree.root(), path));
                }
                return proofs;
            }

            template<typename Hashable, typename T, std::size_t Arity>
            bool validate_compressed_proofs(const std::vector<detail::merkle_proof_impl<detail::merkle_tree_node<T>, Arity>> &proofs,
                                            const std::vector<Hashable> &a) {
                assert(proofs.size() == a.size());
                assert(proofs.size() > 0);
                typedef typename detail::merkle_tree_node<T>::hash_type hash_type;
                typedef typename detail::merkle_tree_node<T>::value_type value_type;
                std::stack<std::pair<value_type, std::size_t>> st;
                auto root = proofs[0].root();
                auto full_proof_size = proofs[0].path().size();
                for (int j = proofs.size() - 1; j >= 0; --j) {
                    auto path = proofs[j].path();
                    assert(path.size() != 0);
                    value_type d = crypto3::hash<hash_type>(a[j]);
                    std::vector<value_type> hashes = {d};
                    for (auto &it : path) {
                        accumulator_set<hash_type> acc;
                        std::size_t i = 0;
                        for (; (i < Arity - 1) && i == it[i].position(); ++i) {
                            crypto3::hash<hash_type>(it[i].hash().begin(), it[i].hash().end(), acc);
                        }
                        crypto3::hash<hash_type>(d.begin(), d.end(), acc);
                        for (; i < Arity - 1; ++i) {
                            crypto3::hash<hash_type>(it[i].hash().begin(), it[i].hash().end(), acc);
                        }
                        d = accumulators::extract::hash<hash_type>(acc);
                        hashes.push_back(d);
                    }
                    while (!st.empty()) {
                        auto top = st.top();
                        if (top.second >= hashes.size()) {
                            break;
                        }
                        if (hashes[top.second] == top.first) {
                            st.pop();
                        } else {
                            return false;
                        }
                    }
                    if (path.size() < full_proof_size) {
                        st.push(std::make_pair(d, path.size()));
                    } else if (d != root) {
                        return false;
                    }
                }
                return true;
            }

            template<typename T, std::size_t Arity>
            using merkle_proof =
                typename std::conditional<nil::crypto3::detail::is_hash<T>::value,
                                          detail::merkle_proof_impl<detail::merkle_tree_node<T>, Arity>,
                                          detail::merkle_proof_impl<T, Arity>>::type;
            
        }    // namespace containers
    }        // namespace crypto3
}    // namespace nil

#endif
