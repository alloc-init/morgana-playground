//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE des_cipher_test

#include <iostream>
#include <cstdint>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <boost/foreach.hpp>
#include <boost/assert.hpp>

#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>

#include <nil/crypto3/block/des.hpp>

#include <nil/crypto3/block/cipher_value.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::block;
using namespace nil::crypto3::detail;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream &, P<K, V> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

class byte_string {
    typedef std::vector<unsigned char> vec_type;

    vec_type s_;

public:
    typedef vec_type::size_type size_type;
    typedef vec_type::value_type value_type;
    typedef vec_type::pointer pointer;
    typedef vec_type::const_pointer const_pointer;
    typedef vec_type::reference reference;
    typedef vec_type::const_reference const_reference;
    typedef vec_type::iterator iterator;
    typedef vec_type::const_iterator const_iterator;

    explicit byte_string(size_type n, const value_type &value = value_type()) : s_(n, value) {
    }

    template<typename InputIterator>
    byte_string(InputIterator first, InputIterator last) : s_(first, last) {
    }

    byte_string(const std::string &src) {
        assert(!(src.size() % 2));
        // const unsigned char* src = static_cast<const unsigned char*>(vsrc);
        s_.resize(src.size() / 2);
        unsigned int j = 0;
        for (unsigned int i = 0; i < src.size();) {
            if (src[i] >= '0' && src[i] <= '9') {
                s_[j] = 16 * (src[i] - '0');
            } else if (src[i] >= 'a' && src[i] <= 'f') {
                s_[j] = 16 * (src[i] - 'a' + 10);
            } else if (src[i] >= 'A' && src[i] <= 'F') {
                s_[j] = 16 * (src[i] - 'A' + 10);
            }
            ++i;
            if (src[i] >= '0' && src[i] <= '9') {
                s_[j] += src[i] - '0';
            } else if (src[i] >= 'a' && src[i] <= 'f') {
                s_[j] += src[i] - 'a' + 10;
            } else if (src[i] >= 'A' && src[i] <= 'F') {
                s_[j] = 16 * (src[i] - 'A' + 10);
            }
            ++i;
            ++j;
        }

        /*for (size_type i = 0; i < len;)
        {
          value_type x;
          if (src[i] >= '0' && src[i] <= '9')
            x = 16 * (src[i] - '0');
          else if (src[i] >= 'a' && src[i] <= 'f')
            x = 16 * (src[i] - 'a' + 10);
          ++i;
          if (src[i] >= '0' && src[i] <= '9')
            x += src[i] - '0';
          else if (src[i] >= 'a' && src[i] <= 'f')
            x += src[i] - 'a' + 10;
          s_.push_back(x);
          ++i;
        }*/
    }

    byte_string(const byte_string &copy) : s_(copy.s_) {
    }

    size_type size() const {
        return s_.size();
    }

    pointer data() {
        return &s_[0];
    }

    const_pointer data() const {
        return &s_[0];
    }

    reference operator[](size_type i) {
        return s_[i];
    }

    const_reference operator[](size_type i) const {
        return s_[i];
    }

    void reserve(size_type n) {
        s_.reserve(n);
    }

    void resize(size_type n, value_type c = value_type()) {
        s_.resize(n, c);
    }

    iterator begin() {
        return s_.begin();
    }

    const_iterator begin() const {
        return s_.begin();
    }

    iterator end() {
        return s_.end();
    }

    const_iterator end() const {
        return s_.end();
    }

    iterator erase(iterator loc) {
        return s_.erase(loc);
    }

    iterator erase(iterator first, iterator last) {
        return s_.erase(first, last);
    }

    friend bool operator==(const byte_string &, const byte_string &);

    friend bool operator!=(const byte_string &, const byte_string &);

    byte_string &operator+=(const byte_string &rhs) {
        s_.insert(s_.end(), rhs.s_.begin(), rhs.s_.end());
        return *this;
    }
};

template<typename charT, class traits>
std::basic_ostream<charT, traits> &operator<<(std::basic_ostream<charT, traits> &out, const byte_string &s) {
    byte_string::size_type bufsize = s.size() * 2 + 1;
    char buf[bufsize];
    for (byte_string::size_type i = 0; i < s.size(); ++i) {
        std::sprintf(buf + i * 2, "%02x", s[i]);
    }
    buf[bufsize - 1] = '\0';
    out << buf;
    return out;
}

inline bool operator==(const byte_string &lhs, const byte_string &rhs) {
    return lhs.s_ == rhs.s_;
}

inline bool operator!=(const byte_string &lhs, const byte_string &rhs) {
    return lhs.s_ != rhs.s_;
}

const char *test_data = "data/des.json";

boost::property_tree::ptree string_data(const char *child_name) {
    boost::property_tree::ptree root_data;
    boost::property_tree::read_json(test_data, root_data);
    return root_data.get_child(child_name);
}

BOOST_AUTO_TEST_SUITE(des_stream_processor_filedriven_test_suite)

BOOST_AUTO_TEST_CASE(des_1) {

    std::vector<char> input = {'\x05', '\x9b', '\x5e', '\x08', '\x51', '\xcf', '\x14', '\x3a'};
    std::vector<char> key = {'\x01', '\x13', '\xb9', '\x70', '\xfd', '\x34', '\xf2', '\xce'};

    std::string out = encrypt<block::des>(input, key);
    
    BOOST_CHECK_EQUAL(out, "86a560f10ec6d85b");
}
/*
BOOST_DATA_TEST_CASE(des_ecb, string_data("ecb_fixed_key"), triples) {

    byte_string const p(triples.first);

    BOOST_FOREACH(boost::property_tree::ptree::value_type pair, triples.second) {
        byte_string const K(pair.first);

        std::string out = encrypt<block::des>(p, K);

        BOOST_CHECK_EQUAL(out, pair.second.data());
    }
}*/

BOOST_AUTO_TEST_SUITE_END()
