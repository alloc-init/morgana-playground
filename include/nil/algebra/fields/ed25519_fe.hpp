//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_ED25519_FE_HPP
#define CRYPTO3_ALGEBRA_ED25519_FE_HPP

namespace nil {
    namespace algebra {
        namespace fields {

            /**
             * An element of the field \\Z/(2^255-19)
             */
            class fe25519 {
            public:
                ~fe25519() {
                    secure_scrub_memory(m_fe, sizeof(m_fe));
                }

                /**
                 * Zero element
                 */
                fe25519(int init = 0) {
                    if (init != 0 && init != 1) {
                        throw std::invalid_argument("Invalid fe25519 initial value");
                    }
                    memset(m_fe, 0, 10 * sizeof(int32_t));
                    m_fe[0] = init;
                }

                fe25519(std::initializer_list<int32_t> x) {
                    if (x.size() != 10) {
                        throw std::invalid_argument("Invalid fe25519 initializer list");
                    }
                    memcpy(m_fe, x.begin(), 10 * sizeof(int32_t));
                }

                fe25519(int64_t h0, int64_t h1, int64_t h2, int64_t h3, int64_t h4, int64_t h5, int64_t h6, int64_t h7,
                        int64_t h8, int64_t h9) {
                    m_fe[0] = static_cast<int32_t>(h0);
                    m_fe[1] = static_cast<int32_t>(h1);
                    m_fe[2] = static_cast<int32_t>(h2);
                    m_fe[3] = static_cast<int32_t>(h3);
                    m_fe[4] = static_cast<int32_t>(h4);
                    m_fe[5] = static_cast<int32_t>(h5);
                    m_fe[6] = static_cast<int32_t>(h6);
                    m_fe[7] = static_cast<int32_t>(h7);
                    m_fe[8] = static_cast<int32_t>(h8);
                    m_fe[9] = static_cast<int32_t>(h9);
                }

                fe25519(const fe25519 &other) = default;

                fe25519 &operator=(const fe25519 &other) = default;

                /*!
                 * @brief Ignores top bit of h.
                 * @param b
                 */
                void from_bytes(const uint8_t s[32]) {
                    int64_t h0 = load_4(s);
                    int64_t h1 = load_3(s + 4) << 6;
                    int64_t h2 = load_3(s + 7) << 5;
                    int64_t h3 = load_3(s + 10) << 3;
                    int64_t h4 = load_3(s + 13) << 2;
                    int64_t h5 = load_4(s + 16);
                    int64_t h6 = load_3(s + 20) << 7;
                    int64_t h7 = load_3(s + 23) << 5;
                    int64_t h8 = load_3(s + 26) << 4;
                    int64_t h9 = (load_3(s + 29) & 0x7fffff) << 2;

                    carry<25, 19>(h9, h0);
                    carry<25>(h1, h2);
                    carry<25>(h3, h4);
                    carry<25>(h5, h6);
                    carry<25>(h7, h8);

                    carry<26>(h0, h1);
                    carry<26>(h2, h3);
                    carry<26>(h4, h5);
                    carry<26>(h6, h7);
                    carry<26>(h8, h9);

                    m_fe[0] = h0;
                    m_fe[1] = h1;
                    m_fe[2] = h2;
                    m_fe[3] = h3;
                    m_fe[4] = h4;
                    m_fe[5] = h5;
                    m_fe[6] = h6;
                    m_fe[7] = h7;
                    m_fe[8] = h8;
                    m_fe[9] = h9;
                }

                /*!
                 * @brief
                 * @param b
                 *
                 * Preconditions:
                 * |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
                 *
                 * Write p=2^255-19; q=floor(h/p).
                 * Basic claim: q = floor(2^(-255)(h + 19 2^(-25)h9 + 2^(-1))).
                 *
                 * Proof:
                 * Have |h|<=p so |q|<=1 so |19^2 2^(-255) q|<1/4.
                 * Also have |h-2^230 h9|<2^231 so |19 2^(-255)(h-2^230 h9)|<1/4.
                 *
                 * Write y=2^(-1)-19^2 2^(-255)q-19 2^(-255)(h-2^230 h9).
                 * Then 0<y<1.
                 *
                 * Write r=h-pq.
                 * Have 0<=r<=p-1=2^255-20.
                 * Thus 0<=r+19(2^-255)r<r+19(2^-255)2^255<=2^255-1.
                 *
                 * Write x=r+19(2^-255)r+y.
                 * Then 0<x<2^255 so floor(2^(-255)x) = 0 so floor(q+2^(-255)x) = q.
                 *
                 * Have q+2^(-255)x = 2^(-255)(h + 19 2^(-25) h9 + 2^(-1))
                 * so floor(2^(-255)(h + 19 2^(-25) h9 + 2^(-1))) = q.
                 */
                void to_bytes(uint8_t s[32]) const {
                    const int64_t X25 = (1 << 25);

                    int32_t h0 = m_fe[0];
                    int32_t h1 = m_fe[1];
                    int32_t h2 = m_fe[2];
                    int32_t h3 = m_fe[3];
                    int32_t h4 = m_fe[4];
                    int32_t h5 = m_fe[5];
                    int32_t h6 = m_fe[6];
                    int32_t h7 = m_fe[7];
                    int32_t h8 = m_fe[8];
                    int32_t h9 = m_fe[9];
                    int32_t q;

                    q = (19 * h9 + ((static_cast<int32_t>(1) << 24))) >> 25;
                    q = (h0 + q) >> 26;
                    q = (h1 + q) >> 25;
                    q = (h2 + q) >> 26;
                    q = (h3 + q) >> 25;
                    q = (h4 + q) >> 26;
                    q = (h5 + q) >> 25;
                    q = (h6 + q) >> 26;
                    q = (h7 + q) >> 25;
                    q = (h8 + q) >> 26;
                    q = (h9 + q) >> 25;

                    /* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */
                    h0 += 19 * q;
                    /* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */

                    carry0<26>(h0, h1);
                    carry0<25>(h1, h2);
                    carry0<26>(h2, h3);
                    carry0<25>(h3, h4);
                    carry0<26>(h4, h5);
                    carry0<25>(h5, h6);
                    carry0<26>(h6, h7);
                    carry0<25>(h7, h8);
                    carry0<26>(h8, h9);

                    int32_t carry9 = h9 >> 25;
                    h9 -= carry9 * X25;
                    /* h10 = carry9 */

                    /*
                    Goal: Output h0+...+2^255 h10-2^255 q, which is between 0 and 2^255-20.
                    Have h0+...+2^230 h9 between 0 and 2^255-1;
                    evidently 2^255 h10-2^255 q = 0.
                    Goal: Output h0+...+2^230 h9.
                    */

                    s[0] = h0 >> 0;
                    s[1] = h0 >> 8;
                    s[2] = h0 >> 16;
                    s[3] = (h0 >> 24) | (h1 << 2);
                    s[4] = h1 >> 6;
                    s[5] = h1 >> 14;
                    s[6] = (h1 >> 22) | (h2 << 3);
                    s[7] = h2 >> 5;
                    s[8] = h2 >> 13;
                    s[9] = (h2 >> 21) | (h3 << 5);
                    s[10] = h3 >> 3;
                    s[11] = h3 >> 11;
                    s[12] = (h3 >> 19) | (h4 << 6);
                    s[13] = h4 >> 2;
                    s[14] = h4 >> 10;
                    s[15] = h4 >> 18;
                    s[16] = h5 >> 0;
                    s[17] = h5 >> 8;
                    s[18] = h5 >> 16;
                    s[19] = (h5 >> 24) | (h6 << 1);
                    s[20] = h6 >> 7;
                    s[21] = h6 >> 15;
                    s[22] = (h6 >> 23) | (h7 << 3);
                    s[23] = h7 >> 5;
                    s[24] = h7 >> 13;
                    s[25] = (h7 >> 21) | (h8 << 4);
                    s[26] = h8 >> 4;
                    s[27] = h8 >> 12;
                    s[28] = (h8 >> 20) | (h9 << 6);
                    s[29] = h9 >> 2;
                    s[30] = h9 >> 10;
                    s[31] = h9 >> 18;
                }

                bool is_zero() const {
                    uint8_t s[32];
                    to_bytes(s);

                    uint8_t sum = 0;
                    for (size_t i = 0; i != 32; ++i) {
                        sum |= s[i];
                    }

                    // TODO avoid ternary here
                    return (sum == 0) ? 1 : 0;
                }

                /*
                return 1 if f is in {1,3,5,...,q-2}
                return 0 if f is in {0,2,4,...,q-1}
                */
                bool is_negative() const {
                    // TODO could avoid most of the to_bytes computation here
                    uint8_t s[32];
                    to_bytes(s);
                    return s[0] & 1;
                }

                static fe25519 add(const fe25519 &a, const fe25519 &b) {
                    fe25519 z;
                    for (size_t i = 0; i != 10; ++i) {
                        z[i] = a[i] + b[i];
                    }
                    return z;
                }

                static fe25519 sub(const fe25519 &a, const fe25519 &b) {
                    fe25519 z;
                    for (size_t i = 0; i != 10; ++i) {
                        z[i] = a[i] - b[i];
                    }
                    return z;
                }

                static fe25519 negate(const fe25519 &a) {
                    fe25519 z;
                    for (size_t i = 0; i != 10; ++i) {
                        z[i] = -a[i];
                    }
                    return z;
                }

                /*
    h = f * g
    Can overlap h with f or g.

    Preconditions:
    |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
    |g| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.

    Postconditions:
    |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.

                Notes on implementation strategy:

                Using schoolbook multiplication.
                Karatsuba would save a little in some cost models.

                Most multiplications by 2 and 19 are 32-bit precomputations;
                cheaper than 64-bit postcomputations.

                There is one remaining multiplication by 19 in the carry chain;
                one *19 precomputation can be merged into this,
                but the resulting data flow is considerably less clean.

                There are 12 carries below.
                10 of them are 2-way parallelizable and vectorizable.
                Can get away with 11 carries, but then data flow is much deeper.

                With tighter constraints on inputs can squeeze carries into int32.
                */
                static fe25519 mul(const fe25519 &a, const fe25519 &b) {
                    const int32_t f0 = f[0];
                    const int32_t f1 = f[1];
                    const int32_t f2 = f[2];
                    const int32_t f3 = f[3];
                    const int32_t f4 = f[4];
                    const int32_t f5 = f[5];
                    const int32_t f6 = f[6];
                    const int32_t f7 = f[7];
                    const int32_t f8 = f[8];
                    const int32_t f9 = f[9];

                    const int32_t g0 = g[0];
                    const int32_t g1 = g[1];
                    const int32_t g2 = g[2];
                    const int32_t g3 = g[3];
                    const int32_t g4 = g[4];
                    const int32_t g5 = g[5];
                    const int32_t g6 = g[6];
                    const int32_t g7 = g[7];
                    const int32_t g8 = g[8];
                    const int32_t g9 = g[9];

                    const int32_t g1_19 = 19 * g1; /* 1.959375*2^29 */
                    const int32_t g2_19 = 19 * g2; /* 1.959375*2^30; still ok */
                    const int32_t g3_19 = 19 * g3;
                    const int32_t g4_19 = 19 * g4;
                    const int32_t g5_19 = 19 * g5;
                    const int32_t g6_19 = 19 * g6;
                    const int32_t g7_19 = 19 * g7;
                    const int32_t g8_19 = 19 * g8;
                    const int32_t g9_19 = 19 * g9;
                    const int32_t f1_2 = 2 * f1;
                    const int32_t f3_2 = 2 * f3;
                    const int32_t f5_2 = 2 * f5;
                    const int32_t f7_2 = 2 * f7;
                    const int32_t f9_2 = 2 * f9;

                    const int64_t f0g0 = f0 * static_cast<int64_t>(g0);
                    const int64_t f0g1 = f0 * static_cast<int64_t>(g1);
                    const int64_t f0g2 = f0 * static_cast<int64_t>(g2);
                    const int64_t f0g3 = f0 * static_cast<int64_t>(g3);
                    const int64_t f0g4 = f0 * static_cast<int64_t>(g4);
                    const int64_t f0g5 = f0 * static_cast<int64_t>(g5);
                    const int64_t f0g6 = f0 * static_cast<int64_t>(g6);
                    const int64_t f0g7 = f0 * static_cast<int64_t>(g7);
                    const int64_t f0g8 = f0 * static_cast<int64_t>(g8);
                    const int64_t f0g9 = f0 * static_cast<int64_t>(g9);
                    const int64_t f1g0 = f1 * static_cast<int64_t>(g0);
                    const int64_t f1g1_2 = f1_2 * static_cast<int64_t>(g1);
                    const int64_t f1g2 = f1 * static_cast<int64_t>(g2);
                    const int64_t f1g3_2 = f1_2 * static_cast<int64_t>(g3);
                    const int64_t f1g4 = f1 * static_cast<int64_t>(g4);
                    const int64_t f1g5_2 = f1_2 * static_cast<int64_t>(g5);
                    const int64_t f1g6 = f1 * static_cast<int64_t>(g6);
                    const int64_t f1g7_2 = f1_2 * static_cast<int64_t>(g7);
                    const int64_t f1g8 = f1 * static_cast<int64_t>(g8);
                    const int64_t f1g9_38 = f1_2 * static_cast<int64_t>(g9_19);
                    const int64_t f2g0 = f2 * static_cast<int64_t>(g0);
                    const int64_t f2g1 = f2 * static_cast<int64_t>(g1);
                    const int64_t f2g2 = f2 * static_cast<int64_t>(g2);
                    const int64_t f2g3 = f2 * static_cast<int64_t>(g3);
                    const int64_t f2g4 = f2 * static_cast<int64_t>(g4);
                    const int64_t f2g5 = f2 * static_cast<int64_t>(g5);
                    const int64_t f2g6 = f2 * static_cast<int64_t>(g6);
                    const int64_t f2g7 = f2 * static_cast<int64_t>(g7);
                    const int64_t f2g8_19 = f2 * static_cast<int64_t>(g8_19);
                    const int64_t f2g9_19 = f2 * static_cast<int64_t>(g9_19);
                    const int64_t f3g0 = f3 * static_cast<int64_t>(g0);
                    const int64_t f3g1_2 = f3_2 * static_cast<int64_t>(g1);
                    const int64_t f3g2 = f3 * static_cast<int64_t>(g2);
                    const int64_t f3g3_2 = f3_2 * static_cast<int64_t>(g3);
                    const int64_t f3g4 = f3 * static_cast<int64_t>(g4);
                    const int64_t f3g5_2 = f3_2 * static_cast<int64_t>(g5);
                    const int64_t f3g6 = f3 * static_cast<int64_t>(g6);
                    const int64_t f3g7_38 = f3_2 * static_cast<int64_t>(g7_19);
                    const int64_t f3g8_19 = f3 * static_cast<int64_t>(g8_19);
                    const int64_t f3g9_38 = f3_2 * static_cast<int64_t>(g9_19);
                    const int64_t f4g0 = f4 * static_cast<int64_t>(g0);
                    const int64_t f4g1 = f4 * static_cast<int64_t>(g1);
                    const int64_t f4g2 = f4 * static_cast<int64_t>(g2);
                    const int64_t f4g3 = f4 * static_cast<int64_t>(g3);
                    const int64_t f4g4 = f4 * static_cast<int64_t>(g4);
                    const int64_t f4g5 = f4 * static_cast<int64_t>(g5);
                    const int64_t f4g6_19 = f4 * static_cast<int64_t>(g6_19);
                    const int64_t f4g7_19 = f4 * static_cast<int64_t>(g7_19);
                    const int64_t f4g8_19 = f4 * static_cast<int64_t>(g8_19);
                    const int64_t f4g9_19 = f4 * static_cast<int64_t>(g9_19);
                    const int64_t f5g0 = f5 * static_cast<int64_t>(g0);
                    const int64_t f5g1_2 = f5_2 * static_cast<int64_t>(g1);
                    const int64_t f5g2 = f5 * static_cast<int64_t>(g2);
                    const int64_t f5g3_2 = f5_2 * static_cast<int64_t>(g3);
                    const int64_t f5g4 = f5 * static_cast<int64_t>(g4);
                    const int64_t f5g5_38 = f5_2 * static_cast<int64_t>(g5_19);
                    const int64_t f5g6_19 = f5 * static_cast<int64_t>(g6_19);
                    const int64_t f5g7_38 = f5_2 * static_cast<int64_t>(g7_19);
                    const int64_t f5g8_19 = f5 * static_cast<int64_t>(g8_19);
                    const int64_t f5g9_38 = f5_2 * static_cast<int64_t>(g9_19);
                    const int64_t f6g0 = f6 * static_cast<int64_t>(g0);
                    const int64_t f6g1 = f6 * static_cast<int64_t>(g1);
                    const int64_t f6g2 = f6 * static_cast<int64_t>(g2);
                    const int64_t f6g3 = f6 * static_cast<int64_t>(g3);
                    const int64_t f6g4_19 = f6 * static_cast<int64_t>(g4_19);
                    const int64_t f6g5_19 = f6 * static_cast<int64_t>(g5_19);
                    const int64_t f6g6_19 = f6 * static_cast<int64_t>(g6_19);
                    const int64_t f6g7_19 = f6 * static_cast<int64_t>(g7_19);
                    const int64_t f6g8_19 = f6 * static_cast<int64_t>(g8_19);
                    const int64_t f6g9_19 = f6 * static_cast<int64_t>(g9_19);
                    const int64_t f7g0 = f7 * static_cast<int64_t>(g0);
                    const int64_t f7g1_2 = f7_2 * static_cast<int64_t>(g1);
                    const int64_t f7g2 = f7 * static_cast<int64_t>(g2);
                    const int64_t f7g3_38 = f7_2 * static_cast<int64_t>(g3_19);
                    const int64_t f7g4_19 = f7 * static_cast<int64_t>(g4_19);
                    const int64_t f7g5_38 = f7_2 * static_cast<int64_t>(g5_19);
                    const int64_t f7g6_19 = f7 * static_cast<int64_t>(g6_19);
                    const int64_t f7g7_38 = f7_2 * static_cast<int64_t>(g7_19);
                    const int64_t f7g8_19 = f7 * static_cast<int64_t>(g8_19);
                    const int64_t f7g9_38 = f7_2 * static_cast<int64_t>(g9_19);
                    const int64_t f8g0 = f8 * static_cast<int64_t>(g0);
                    const int64_t f8g1 = f8 * static_cast<int64_t>(g1);
                    const int64_t f8g2_19 = f8 * static_cast<int64_t>(g2_19);
                    const int64_t f8g3_19 = f8 * static_cast<int64_t>(g3_19);
                    const int64_t f8g4_19 = f8 * static_cast<int64_t>(g4_19);
                    const int64_t f8g5_19 = f8 * static_cast<int64_t>(g5_19);
                    const int64_t f8g6_19 = f8 * static_cast<int64_t>(g6_19);
                    const int64_t f8g7_19 = f8 * static_cast<int64_t>(g7_19);
                    const int64_t f8g8_19 = f8 * static_cast<int64_t>(g8_19);
                    const int64_t f8g9_19 = f8 * static_cast<int64_t>(g9_19);
                    const int64_t f9g0 = f9 * static_cast<int64_t>(g0);
                    const int64_t f9g1_38 = f9_2 * static_cast<int64_t>(g1_19);
                    const int64_t f9g2_19 = f9 * static_cast<int64_t>(g2_19);
                    const int64_t f9g3_38 = f9_2 * static_cast<int64_t>(g3_19);
                    const int64_t f9g4_19 = f9 * static_cast<int64_t>(g4_19);
                    const int64_t f9g5_38 = f9_2 * static_cast<int64_t>(g5_19);
                    const int64_t f9g6_19 = f9 * static_cast<int64_t>(g6_19);
                    const int64_t f9g7_38 = f9_2 * static_cast<int64_t>(g7_19);
                    const int64_t f9g8_19 = f9 * static_cast<int64_t>(g8_19);
                    const int64_t f9g9_38 = f9_2 * static_cast<int64_t>(g9_19);

                    int64_t h0 =
                        f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38;
                    int64_t h1 =
                        f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19;
                    int64_t h2 = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38;
                    int64_t h3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19;
                    int64_t h4 = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38;
                    int64_t h5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19;
                    int64_t h6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38;
                    int64_t h7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19;
                    int64_t h8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38;
                    int64_t h9 = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0;

                    /*
                    |h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
                    i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
                    |h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
                    i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9
                    */
                    carry<26>(h0, h1);
                    carry<26>(h4, h5);

                    /* |h0| <= 2^25 */
                    /* |h4| <= 2^25 */
                    /* |h1| <= 1.71*2^59 */
                    /* |h5| <= 1.71*2^59 */

                    carry<25>(h1, h2);
                    carry<25>(h5, h6);

                    /* |h1| <= 2^24; from now on fits into int32 */
                    /* |h5| <= 2^24; from now on fits into int32 */
                    /* |h2| <= 1.41*2^60 */
                    /* |h6| <= 1.41*2^60 */

                    carry<26>(h2, h3);
                    carry<26>(h6, h7);
                    /* |h2| <= 2^25; from now on fits into int32 unchanged */
                    /* |h6| <= 2^25; from now on fits into int32 unchanged */
                    /* |h3| <= 1.71*2^59 */
                    /* |h7| <= 1.71*2^59 */

                    carry<25>(h3, h4);
                    carry<25>(h7, h8);
                    /* |h3| <= 2^24; from now on fits into int32 unchanged */
                    /* |h7| <= 2^24; from now on fits into int32 unchanged */
                    /* |h4| <= 1.72*2^34 */
                    /* |h8| <= 1.41*2^60 */

                    carry<26>(h4, h5);
                    carry<26>(h8, h9);
                    /* |h4| <= 2^25; from now on fits into int32 unchanged */
                    /* |h8| <= 2^25; from now on fits into int32 unchanged */
                    /* |h5| <= 1.01*2^24 */
                    /* |h9| <= 1.71*2^59 */

                    carry<25, 19>(h9, h0);

                    /* |h9| <= 2^24; from now on fits into int32 unchanged */
                    /* |h0| <= 1.1*2^39 */

                    carry<26>(h0, h1);
                    /* |h0| <= 2^25; from now on fits into int32 unchanged */
                    /* |h1| <= 1.01*2^24 */

                    return fe25519(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
                }

                /*!
                 * @brief
                 * h = f * f
                 * Can overlap h with f.
                 *
                 * Preconditions:
                 * |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
                 *
                 * Postconditions:
                 * |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
                 *
                 * See fe_mul.c for discussion of implementation strategy.
                 *
                 * @param a
                 * @param iter
                 * @return
                 */
                static fe25519 sqr_iter(const fe25519 &a, size_t iter) {
                    int32_t f0 = f[0];
                    int32_t f1 = f[1];
                    int32_t f2 = f[2];
                    int32_t f3 = f[3];
                    int32_t f4 = f[4];
                    int32_t f5 = f[5];
                    int32_t f6 = f[6];
                    int32_t f7 = f[7];
                    int32_t f8 = f[8];
                    int32_t f9 = f[9];

                    for (size_t i = 0; i != iter; ++i) {
                        const int32_t f0_2 = 2 * f0;
                        const int32_t f1_2 = 2 * f1;
                        const int32_t f2_2 = 2 * f2;
                        const int32_t f3_2 = 2 * f3;
                        const int32_t f4_2 = 2 * f4;
                        const int32_t f5_2 = 2 * f5;
                        const int32_t f6_2 = 2 * f6;
                        const int32_t f7_2 = 2 * f7;
                        const int32_t f5_38 = 38 * f5; /* 1.959375*2^30 */
                        const int32_t f6_19 = 19 * f6; /* 1.959375*2^30 */
                        const int32_t f7_38 = 38 * f7; /* 1.959375*2^30 */
                        const int32_t f8_19 = 19 * f8; /* 1.959375*2^30 */
                        const int32_t f9_38 = 38 * f9; /* 1.959375*2^30 */

                        const int64_t f0f0 = f0 * static_cast<int64_t>(f0);
                        const int64_t f0f1_2 = f0_2 * static_cast<int64_t>(f1);
                        const int64_t f0f2_2 = f0_2 * static_cast<int64_t>(f2);
                        const int64_t f0f3_2 = f0_2 * static_cast<int64_t>(f3);
                        const int64_t f0f4_2 = f0_2 * static_cast<int64_t>(f4);
                        const int64_t f0f5_2 = f0_2 * static_cast<int64_t>(f5);
                        const int64_t f0f6_2 = f0_2 * static_cast<int64_t>(f6);
                        const int64_t f0f7_2 = f0_2 * static_cast<int64_t>(f7);
                        const int64_t f0f8_2 = f0_2 * static_cast<int64_t>(f8);
                        const int64_t f0f9_2 = f0_2 * static_cast<int64_t>(f9);
                        const int64_t f1f1_2 = f1_2 * static_cast<int64_t>(f1);
                        const int64_t f1f2_2 = f1_2 * static_cast<int64_t>(f2);
                        const int64_t f1f3_4 = f1_2 * static_cast<int64_t>(f3_2);
                        const int64_t f1f4_2 = f1_2 * static_cast<int64_t>(f4);
                        const int64_t f1f5_4 = f1_2 * static_cast<int64_t>(f5_2);
                        const int64_t f1f6_2 = f1_2 * static_cast<int64_t>(f6);
                        const int64_t f1f7_4 = f1_2 * static_cast<int64_t>(f7_2);
                        const int64_t f1f8_2 = f1_2 * static_cast<int64_t>(f8);
                        const int64_t f1f9_76 = f1_2 * static_cast<int64_t>(f9_38);
                        const int64_t f2f2 = f2 * static_cast<int64_t>(f2);
                        const int64_t f2f3_2 = f2_2 * static_cast<int64_t>(f3);
                        const int64_t f2f4_2 = f2_2 * static_cast<int64_t>(f4);
                        const int64_t f2f5_2 = f2_2 * static_cast<int64_t>(f5);
                        const int64_t f2f6_2 = f2_2 * static_cast<int64_t>(f6);
                        const int64_t f2f7_2 = f2_2 * static_cast<int64_t>(f7);
                        const int64_t f2f8_38 = f2_2 * static_cast<int64_t>(f8_19);
                        const int64_t f2f9_38 = f2 * static_cast<int64_t>(f9_38);
                        const int64_t f3f3_2 = f3_2 * static_cast<int64_t>(f3);
                        const int64_t f3f4_2 = f3_2 * static_cast<int64_t>(f4);
                        const int64_t f3f5_4 = f3_2 * static_cast<int64_t>(f5_2);
                        const int64_t f3f6_2 = f3_2 * static_cast<int64_t>(f6);
                        const int64_t f3f7_76 = f3_2 * static_cast<int64_t>(f7_38);
                        const int64_t f3f8_38 = f3_2 * static_cast<int64_t>(f8_19);
                        const int64_t f3f9_76 = f3_2 * static_cast<int64_t>(f9_38);
                        const int64_t f4f4 = f4 * static_cast<int64_t>(f4);
                        const int64_t f4f5_2 = f4_2 * static_cast<int64_t>(f5);
                        const int64_t f4f6_38 = f4_2 * static_cast<int64_t>(f6_19);
                        const int64_t f4f7_38 = f4 * static_cast<int64_t>(f7_38);
                        const int64_t f4f8_38 = f4_2 * static_cast<int64_t>(f8_19);
                        const int64_t f4f9_38 = f4 * static_cast<int64_t>(f9_38);
                        const int64_t f5f5_38 = f5 * static_cast<int64_t>(f5_38);
                        const int64_t f5f6_38 = f5_2 * static_cast<int64_t>(f6_19);
                        const int64_t f5f7_76 = f5_2 * static_cast<int64_t>(f7_38);
                        const int64_t f5f8_38 = f5_2 * static_cast<int64_t>(f8_19);
                        const int64_t f5f9_76 = f5_2 * static_cast<int64_t>(f9_38);
                        const int64_t f6f6_19 = f6 * static_cast<int64_t>(f6_19);
                        const int64_t f6f7_38 = f6 * static_cast<int64_t>(f7_38);
                        const int64_t f6f8_38 = f6_2 * static_cast<int64_t>(f8_19);
                        const int64_t f6f9_38 = f6 * static_cast<int64_t>(f9_38);
                        const int64_t f7f7_38 = f7 * static_cast<int64_t>(f7_38);
                        const int64_t f7f8_38 = f7_2 * static_cast<int64_t>(f8_19);
                        const int64_t f7f9_76 = f7_2 * static_cast<int64_t>(f9_38);
                        const int64_t f8f8_19 = f8 * static_cast<int64_t>(f8_19);
                        const int64_t f8f9_38 = f8 * static_cast<int64_t>(f9_38);
                        const int64_t f9f9_38 = f9 * static_cast<int64_t>(f9_38);

                        int64_t h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
                        int64_t h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
                        int64_t h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
                        int64_t h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
                        int64_t h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
                        int64_t h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
                        int64_t h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
                        int64_t h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
                        int64_t h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
                        int64_t h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;

                        carry<26>(h0, h1);
                        carry<26>(h4, h5);
                        carry<25>(h1, h2);
                        carry<25>(h5, h6);
                        carry<26>(h2, h3);
                        carry<26>(h6, h7);

                        carry<25>(h3, h4);
                        carry<25>(h7, h8);

                        carry<26>(h4, h5);
                        carry<26>(h8, h9);
                        carry<25, 19>(h9, h0);
                        carry<26>(h0, h1);

                        f0 = h0;
                        f1 = h1;
                        f2 = h2;
                        f3 = h3;
                        f4 = h4;
                        f5 = h5;
                        f6 = h6;
                        f7 = h7;
                        f8 = h8;
                        f9 = h9;
                    }

                    return fe25519(f0, f1, f2, f3, f4, f5, f6, f7, f8, f9);
                }

                static fe25519 sqr(const fe25519 &a) {
                    return sqr_iter(a, 1);
                }

                /*!
                 * @brief
                 * @param a
                 * @return
                 *
                 * h = 2 * f * f
                 * Can overlap h with f.
                 *
                 * Preconditions:
                 * |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
                 *
                 * Postconditions:
                 * |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
                 *
                 * See fe_mul.c for discussion of implementation strategy.
                 */

                // static
                static fe25519 sqr2(const fe25519 &a) {
                    const int32_t f0 = f[0];
                    const int32_t f1 = f[1];
                    const int32_t f2 = f[2];
                    const int32_t f3 = f[3];
                    const int32_t f4 = f[4];
                    const int32_t f5 = f[5];
                    const int32_t f6 = f[6];
                    const int32_t f7 = f[7];
                    const int32_t f8 = f[8];
                    const int32_t f9 = f[9];
                    const int32_t f0_2 = 2 * f0;
                    const int32_t f1_2 = 2 * f1;
                    const int32_t f2_2 = 2 * f2;
                    const int32_t f3_2 = 2 * f3;
                    const int32_t f4_2 = 2 * f4;
                    const int32_t f5_2 = 2 * f5;
                    const int32_t f6_2 = 2 * f6;
                    const int32_t f7_2 = 2 * f7;
                    const int32_t f5_38 = 38 * f5; /* 1.959375*2^30 */
                    const int32_t f6_19 = 19 * f6; /* 1.959375*2^30 */
                    const int32_t f7_38 = 38 * f7; /* 1.959375*2^30 */
                    const int32_t f8_19 = 19 * f8; /* 1.959375*2^30 */
                    const int32_t f9_38 = 38 * f9; /* 1.959375*2^30 */
                    const int64_t f0f0 = f0 * static_cast<int64_t>(f0);
                    const int64_t f0f1_2 = f0_2 * static_cast<int64_t>(f1);
                    const int64_t f0f2_2 = f0_2 * static_cast<int64_t>(f2);
                    const int64_t f0f3_2 = f0_2 * static_cast<int64_t>(f3);
                    const int64_t f0f4_2 = f0_2 * static_cast<int64_t>(f4);
                    const int64_t f0f5_2 = f0_2 * static_cast<int64_t>(f5);
                    const int64_t f0f6_2 = f0_2 * static_cast<int64_t>(f6);
                    const int64_t f0f7_2 = f0_2 * static_cast<int64_t>(f7);
                    const int64_t f0f8_2 = f0_2 * static_cast<int64_t>(f8);
                    const int64_t f0f9_2 = f0_2 * static_cast<int64_t>(f9);
                    const int64_t f1f1_2 = f1_2 * static_cast<int64_t>(f1);
                    const int64_t f1f2_2 = f1_2 * static_cast<int64_t>(f2);
                    const int64_t f1f3_4 = f1_2 * static_cast<int64_t>(f3_2);
                    const int64_t f1f4_2 = f1_2 * static_cast<int64_t>(f4);
                    const int64_t f1f5_4 = f1_2 * static_cast<int64_t>(f5_2);
                    const int64_t f1f6_2 = f1_2 * static_cast<int64_t>(f6);
                    const int64_t f1f7_4 = f1_2 * static_cast<int64_t>(f7_2);
                    const int64_t f1f8_2 = f1_2 * static_cast<int64_t>(f8);
                    const int64_t f1f9_76 = f1_2 * static_cast<int64_t>(f9_38);
                    const int64_t f2f2 = f2 * static_cast<int64_t>(f2);
                    const int64_t f2f3_2 = f2_2 * static_cast<int64_t>(f3);
                    const int64_t f2f4_2 = f2_2 * static_cast<int64_t>(f4);
                    const int64_t f2f5_2 = f2_2 * static_cast<int64_t>(f5);
                    const int64_t f2f6_2 = f2_2 * static_cast<int64_t>(f6);
                    const int64_t f2f7_2 = f2_2 * static_cast<int64_t>(f7);
                    const int64_t f2f8_38 = f2_2 * static_cast<int64_t>(f8_19);
                    const int64_t f2f9_38 = f2 * static_cast<int64_t>(f9_38);
                    const int64_t f3f3_2 = f3_2 * static_cast<int64_t>(f3);
                    const int64_t f3f4_2 = f3_2 * static_cast<int64_t>(f4);
                    const int64_t f3f5_4 = f3_2 * static_cast<int64_t>(f5_2);
                    const int64_t f3f6_2 = f3_2 * static_cast<int64_t>(f6);
                    const int64_t f3f7_76 = f3_2 * static_cast<int64_t>(f7_38);
                    const int64_t f3f8_38 = f3_2 * static_cast<int64_t>(f8_19);
                    const int64_t f3f9_76 = f3_2 * static_cast<int64_t>(f9_38);
                    const int64_t f4f4 = f4 * static_cast<int64_t>(f4);
                    const int64_t f4f5_2 = f4_2 * static_cast<int64_t>(f5);
                    const int64_t f4f6_38 = f4_2 * static_cast<int64_t>(f6_19);
                    const int64_t f4f7_38 = f4 * static_cast<int64_t>(f7_38);
                    const int64_t f4f8_38 = f4_2 * static_cast<int64_t>(f8_19);
                    const int64_t f4f9_38 = f4 * static_cast<int64_t>(f9_38);
                    const int64_t f5f5_38 = f5 * static_cast<int64_t>(f5_38);
                    const int64_t f5f6_38 = f5_2 * static_cast<int64_t>(f6_19);
                    const int64_t f5f7_76 = f5_2 * static_cast<int64_t>(f7_38);
                    const int64_t f5f8_38 = f5_2 * static_cast<int64_t>(f8_19);
                    const int64_t f5f9_76 = f5_2 * static_cast<int64_t>(f9_38);
                    const int64_t f6f6_19 = f6 * static_cast<int64_t>(f6_19);
                    const int64_t f6f7_38 = f6 * static_cast<int64_t>(f7_38);
                    const int64_t f6f8_38 = f6_2 * static_cast<int64_t>(f8_19);
                    const int64_t f6f9_38 = f6 * static_cast<int64_t>(f9_38);
                    const int64_t f7f7_38 = f7 * static_cast<int64_t>(f7_38);
                    const int64_t f7f8_38 = f7_2 * static_cast<int64_t>(f8_19);
                    const int64_t f7f9_76 = f7_2 * static_cast<int64_t>(f9_38);
                    const int64_t f8f8_19 = f8 * static_cast<int64_t>(f8_19);
                    const int64_t f8f9_38 = f8 * static_cast<int64_t>(f9_38);
                    const int64_t f9f9_38 = f9 * static_cast<int64_t>(f9_38);

                    int64_t h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
                    int64_t h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
                    int64_t h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
                    int64_t h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
                    int64_t h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
                    int64_t h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
                    int64_t h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
                    int64_t h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
                    int64_t h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
                    int64_t h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;

                    h0 += h0;
                    h1 += h1;
                    h2 += h2;
                    h3 += h3;
                    h4 += h4;
                    h5 += h5;
                    h6 += h6;
                    h7 += h7;
                    h8 += h8;
                    h9 += h9;

                    carry<26>(h0, h1);
                    carry<26>(h4, h5);

                    carry<25>(h1, h2);
                    carry<25>(h5, h6);

                    carry<26>(h2, h3);
                    carry<26>(h6, h7);

                    carry<25>(h3, h4);
                    carry<25>(h7, h8);
                    carry<26>(h4, h5);
                    carry<26>(h8, h9);
                    carry<25, 19>(h9, h0);
                    carry<26>(h0, h1);

                    return fe25519(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
                }

                static fe25519 pow_22523(const fe25519 &a) {
                    fe t0;
                    fe t1;
                    fe t2;

                    fe_sq(t0, z);
                    fe_sq_iter(t1, t0, 2);
                    fe_mul(t1, z, t1);
                    fe_mul(t0, t0, t1);
                    fe_sq(t0, t0);
                    fe_mul(t0, t1, t0);
                    fe_sq_iter(t1, t0, 5);
                    fe_mul(t0, t1, t0);
                    fe_sq_iter(t1, t0, 10);
                    fe_mul(t1, t1, t0);
                    fe_sq_iter(t2, t1, 20);
                    fe_mul(t1, t2, t1);
                    fe_sq_iter(t1, t1, 10);
                    fe_mul(t0, t1, t0);
                    fe_sq_iter(t1, t0, 50);
                    fe_mul(t1, t1, t0);
                    fe_sq_iter(t2, t1, 100);
                    fe_mul(t1, t2, t1);
                    fe_sq_iter(t1, t1, 50);
                    fe_mul(t0, t1, t0);
                    fe_sq_iter(t0, t0, 2);

                    fe_mul(t0, t0, z);
                    return t0;
                }

                static fe25519 invert(const fe25519 &a) {
                    fe t0;
                    fe t1;
                    fe t2;
                    fe t3;

                    fe_sq(t0, z);
                    fe_sq_iter(t1, t0, 2);
                    fe_mul(t1, z, t1);
                    fe_mul(t0, t0, t1);
                    fe_sq(t2, t0);
                    fe_mul(t1, t1, t2);
                    fe_sq_iter(t2, t1, 5);
                    fe_mul(t1, t2, t1);
                    fe_sq_iter(t2, t1, 10);
                    fe_mul(t2, t2, t1);
                    fe_sq_iter(t3, t2, 20);
                    fe_mul(t2, t3, t2);
                    fe_sq_iter(t2, t2, 10);
                    fe_mul(t1, t2, t1);
                    fe_sq_iter(t2, t1, 50);
                    fe_mul(t2, t2, t1);
                    fe_sq_iter(t3, t2, 100);
                    fe_mul(t2, t3, t2);
                    fe_sq_iter(t2, t2, 50);
                    fe_mul(t1, t2, t1);
                    fe_sq_iter(t1, t1, 5);

                    fe_mul(t0, t1, t0);
                    return t0;
                }

                // TODO remove
                int32_t operator[](size_t i) const {
                    return m_fe[i];
                }

                int32_t &operator[](size_t i) {
                    return m_fe[i];
                }

            private:
                int32_t m_fe[10];
            };

            typedef fe25519 fe;

            /*
            fe means field element.
            Here the field is
            An element t, entries t[0]...t[9], represents the integer
            t[0]+2^26 t[1]+2^51 t[2]+2^77 t[3]+2^102 t[4]+...+2^230 t[9].
            Bounds on each t[i] vary depending on context.
            */

            inline void fe_frombytes(fe &x, const uint8_t *b) {
                x.from_bytes(b);
            }

            inline void fe_tobytes(uint8_t *b, const fe &x) {
                x.to_bytes(b);
            }

            inline void fe_copy(fe &a, const fe &b) {
                a = b;
            }

            inline int fe_isnonzero(const fe &x) {
                return x.is_zero() ? 0 : 1;
            }

            inline int fe_isnegative(const fe &x) {
                return x < 0;
            }

            inline void fe_0(fe &x) {
                x = fe25519();
            }

            inline void fe_1(fe &x) {
                x = fe25519(1);
            }

            inline void fe_add(fe &x, const fe &a, const fe &b) {
                x = fe25519::add(a, b);
            }

            inline void fe_sub(fe &x, const fe &a, const fe &b) {
                x = fe25519::sub(a, b);
            }

            inline void fe_neg(fe &x, const fe &z) {
                x = fe25519::fe25519(z);
            }

            inline void fe_mul(fe &x, const fe &a, const fe &b) {
                x = fe25519::mul(a, b);
            }

            inline void fe_sq(fe &x, const fe &z) {
                x = fe25519::fe25519(z);
            }

            inline void fe_sq_iter(fe &x, const fe &z, size_t iter) {
                x = fe25519::sqr_iter(z, iter);
            }

            inline void fe_sq2(fe &x, const fe &z) {
                x = fe25519::fe25519(z);
            }

            inline void fe_invert(fe &x, const fe &z) {
                x = fe25519::fe25519(z);
            }

            inline void fe_pow22523(fe &x, const fe &y) {
                x = fe25519::fe25519(y);
            }
        }   // namespace fields
    }    // namespace crypto3
}    // namespace nil

#endif
