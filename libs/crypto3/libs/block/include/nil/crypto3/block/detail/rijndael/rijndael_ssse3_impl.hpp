//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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
// @file AES using SSSE3
//
// @brief This is more or less a direct translation of public domain x86-64
// assembly written by Mike Hamburg, described in "Accelerating AES
// with Vector Permute Instructions" (CHES 2009). His original code is
// available at https://crypto.stanford.edu/vpaes/
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SSSE3_RIJNDAEL_IMPL_HPP
#define CRYPTO3_SSSE3_RIJNDAEL_IMPL_HPP

#include <cstddef>

#include <tmmintrin.h>

#include <boost/static_assert.hpp>

#include <nil/crypto3/detail/config.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                /*!
                 * @cond DETAIL_IMPL
                 */

                const __m128i low_nibs = _mm_set1_epi8(0x0F);

                const __m128i k_ipt1 = _mm_set_epi32(0xCABAE090, 0x52227808, 0xC2B2E898, 0x5A2A7000);
                const __m128i k_ipt2 = _mm_set_epi32(0xCD80B1FC, 0xB0FDCC81, 0x4C01307D, 0x317C4D00);

                const __m128i k_inv1 = _mm_set_epi32(0x04070309, 0x0A0B0C02, 0x0E05060F, 0x0D080180);
                const __m128i k_inv2 = _mm_set_epi32(0x030D0E0C, 0x02050809, 0x01040A06, 0x0F0B0780);

                const __m128i sb1u = _mm_set_epi32(0xA5DF7A6E, 0x142AF544, 0xB19BE18F, 0xCB503E00);
                const __m128i sb1t = _mm_set_epi32(0x3BF7CCC1, 0x0D2ED9EF, 0x3618D415, 0xFAE22300);

                const __m128i mc_forward[4] = {_mm_set_epi32(0x0C0F0E0D, 0x080B0A09, 0x04070605, 0x00030201),
                                               _mm_set_epi32(0x00030201, 0x0C0F0E0D, 0x080B0A09, 0x04070605),
                                               _mm_set_epi32(0x04070605, 0x00030201, 0x0C0F0E0D, 0x080B0A09),
                                               _mm_set_epi32(0x080B0A09, 0x04070605, 0x00030201, 0x0C0F0E0D)};

                const __m128i sr[4] = {
                    _mm_set_epi32(0x0F0E0D0C, 0x0B0A0908, 0x07060504, 0x03020100),
                    _mm_set_epi32(0x0B06010C, 0x07020D08, 0x030E0904, 0x0F0A0500),
                    _mm_set_epi32(0x070E050C, 0x030A0108, 0x0F060D04, 0x0B020900),
                    _mm_set_epi32(0x0306090C, 0x0F020508, 0x0B0E0104, 0x070A0D00),
                };

#define mm_xor3(x, y, z) _mm_xor_si128(x, _mm_xor_si128(y, z))

                BOOST_ATTRIBUTE_TARGET("ssse3")
                __m128i aes_schedule_transform(__m128i input, __m128i table_1, __m128i table_2) {
                    __m128i i_1 = _mm_and_si128(low_nibs, input);
                    __m128i i_2 = _mm_srli_epi32(_mm_andnot_si128(low_nibs, input), 4);

                    return _mm_xor_si128(_mm_shuffle_epi8(table_1, i_1), _mm_shuffle_epi8(table_2, i_2));
                }

                BOOST_ATTRIBUTE_TARGET("ssse3") __m128i aes_schedule_mangle(__m128i K, uint8_t round_no) {
                    __m128i t = _mm_shuffle_epi8(_mm_xor_si128(K, _mm_set1_epi8(0x5B)), mc_forward[0]);

                    __m128i t2 = t;

                    t = _mm_shuffle_epi8(t, mc_forward[0]);

                    t2 = mm_xor3(t2, t, _mm_shuffle_epi8(t, mc_forward[0]));

                    return _mm_shuffle_epi8(t2, sr[round_no % 4]);
                }

                BOOST_ATTRIBUTE_TARGET("ssse3") __m128i aes_schedule_192_smear(__m128i x, __m128i y) {
                    return mm_xor3(y, _mm_shuffle_epi32(x, 0xFE), _mm_shuffle_epi32(y, 0x80));
                }

                BOOST_ATTRIBUTE_TARGET("ssse3") __m128i aes_schedule_mangle_dec(__m128i K, uint8_t round_no) {
                    const __m128i dsk[8] = {_mm_set_epi32(0x4AED9334, 0x82255BFC, 0xB6116FC8, 0x7ED9A700),
                                            _mm_set_epi32(0x8BB89FAC, 0xE9DAFDCE, 0x45765162, 0x27143300),
                                            _mm_set_epi32(0x4622EE8A, 0xADC90561, 0x27438FEB, 0xCCA86400),
                                            _mm_set_epi32(0x73AEE13C, 0xBD602FF2, 0x815C13CE, 0x4F92DD00),
                                            _mm_set_epi32(0xF83F3EF9, 0xFA3D3CFB, 0x03C4C502, 0x01C6C700),
                                            _mm_set_epi32(0xA5526A9D, 0x7384BC4B, 0xEE1921D6, 0x38CFF700),
                                            _mm_set_epi32(0xA080D3F3, 0x10306343, 0xE3C390B0, 0x53732000),
                                            _mm_set_epi32(0x2F45AEC4, 0x8CE60D67, 0xA0CA214B, 0x036982E8)};

                    __m128i t = aes_schedule_transform(K, dsk[0], dsk[1]);
                    __m128i output = _mm_shuffle_epi8(t, mc_forward[0]);

                    t = aes_schedule_transform(t, dsk[2], dsk[3]);
                    output = _mm_shuffle_epi8(_mm_xor_si128(t, output), mc_forward[0]);

                    t = aes_schedule_transform(t, dsk[4], dsk[5]);
                    output = _mm_shuffle_epi8(_mm_xor_si128(t, output), mc_forward[0]);

                    t = aes_schedule_transform(t, dsk[6], dsk[7]);
                    output = _mm_shuffle_epi8(_mm_xor_si128(t, output), mc_forward[0]);

                    return _mm_shuffle_epi8(output, sr[round_no % 4]);
                }

                BOOST_ATTRIBUTE_TARGET("ssse3") __m128i aes_schedule_mangle_last(__m128i K, uint8_t round_no) {
                    const __m128i out_tr1 = _mm_set_epi32(0xF7974121, 0xDEBE6808, 0xFF9F4929, 0xD6B66000);
                    const __m128i out_tr2 = _mm_set_epi32(0xE10D5DB1, 0xB05C0CE0, 0x01EDBD51, 0x50BCEC00);

                    K = _mm_shuffle_epi8(K, sr[round_no % 4]);
                    K = _mm_xor_si128(K, _mm_set1_epi8(0x5B));
                    return aes_schedule_transform(K, out_tr1, out_tr2);
                }

                BOOST_ATTRIBUTE_TARGET("ssse3") __m128i aes_schedule_mangle_last_dec(__m128i K) {
                    const __m128i deskew1 = _mm_set_epi32(0x1DFEB95A, 0x5DBEF91A, 0x07E4A340, 0x47A4E300);
                    const __m128i deskew2 = _mm_set_epi32(0x2841C2AB, 0xF49D1E77, 0x5F36B5DC, 0x83EA6900);

                    K = _mm_xor_si128(K, _mm_set1_epi8(0x5B));
                    return aes_schedule_transform(K, deskew1, deskew2);
                }

                BOOST_ATTRIBUTE_TARGET("ssse3") __m128i aes_schedule_round(__m128i *rcon, __m128i input1, __m128i input2) {
                    if (rcon) {
                        input2 = _mm_xor_si128(_mm_alignr_epi8(_mm_setzero_si128(), *rcon, 15), input2);

                        *rcon = _mm_alignr_epi8(*rcon, *rcon, 15);    // next rcon

                        input1 = _mm_shuffle_epi32(input1, 0xFF);    // rotate
                        input1 = _mm_alignr_epi8(input1, input1, 1);
                    }

                    __m128i smeared = _mm_xor_si128(input2, _mm_slli_si128(input2, 4));
                    smeared = mm_xor3(smeared, _mm_slli_si128(smeared, 8), _mm_set1_epi8(0x5B));

                    __m128i t = _mm_srli_epi32(_mm_andnot_si128(low_nibs, input1), 4);

                    input1 = _mm_and_si128(low_nibs, input1);

                    __m128i t2 = _mm_shuffle_epi8(k_inv2, input1);

                    input1 = _mm_xor_si128(input1, t);

                    __m128i t3 = _mm_xor_si128(t2, _mm_shuffle_epi8(k_inv1, t));
                    __m128i t4 = _mm_xor_si128(t2, _mm_shuffle_epi8(k_inv1, input1));

                    __m128i t5 = _mm_xor_si128(input1, _mm_shuffle_epi8(k_inv1, t3));
                    __m128i t6 = _mm_xor_si128(t, _mm_shuffle_epi8(k_inv1, t4));

                    return mm_xor3(_mm_shuffle_epi8(sb1u, t5), _mm_shuffle_epi8(sb1t, t6), smeared);
                }

                BOOST_ATTRIBUTE_TARGET("ssse3") __m128i aes_ssse3_encrypt(__m128i B, const __m128i *keys, size_t rounds) {
                    const __m128i sb2u = _mm_set_epi32(0x5EB7E955, 0xBC982FCD, 0xE27A93C6, 0x0B712400);
                    const __m128i sb2t = _mm_set_epi32(0xC2A163C8, 0xAB82234A, 0x69EB8840, 0x0AE12900);

                    const __m128i sbou = _mm_set_epi32(0x15AABF7A, 0xC502A878, 0xD0D26D17, 0x6FBDC700);
                    const __m128i sbot = _mm_set_epi32(0x8E1E90D1, 0x412B35FA, 0xCFE474A5, 0x5FBB6A00);

                    const __m128i mc_backward[4] = {
                        _mm_set_epi32(0x0E0D0C0F, 0x0A09080B, 0x06050407, 0x02010003),
                        _mm_set_epi32(0x0A09080B, 0x06050407, 0x02010003, 0x0E0D0C0F),
                        _mm_set_epi32(0x06050407, 0x02010003, 0x0E0D0C0F, 0x0A09080B),
                        _mm_set_epi32(0x02010003, 0x0E0D0C0F, 0x0A09080B, 0x06050407),
                    };

                    B = mm_xor3(_mm_shuffle_epi8(k_ipt1, _mm_and_si128(low_nibs, B)),
                                _mm_shuffle_epi8(k_ipt2, _mm_srli_epi32(_mm_andnot_si128(low_nibs, B), 4)),
                                _mm_loadu_si128(keys));

                    for (size_t r = 1;; ++r) {
                        const __m128i K = _mm_loadu_si128(keys + r);

                        __m128i t = _mm_srli_epi32(_mm_andnot_si128(low_nibs, B), 4);

                        B = _mm_and_si128(low_nibs, B);

                        __m128i t2 = _mm_shuffle_epi8(k_inv2, B);

                        B = _mm_xor_si128(B, t);

                        __m128i t3 = _mm_xor_si128(t2, _mm_shuffle_epi8(k_inv1, t));
                        __m128i t4 = _mm_xor_si128(t2, _mm_shuffle_epi8(k_inv1, B));

                        __m128i t5 = _mm_xor_si128(B, _mm_shuffle_epi8(k_inv1, t3));
                        __m128i t6 = _mm_xor_si128(t, _mm_shuffle_epi8(k_inv1, t4));

                        if (r == rounds) {
                            B = _mm_shuffle_epi8(mm_xor3(_mm_shuffle_epi8(sbou, t5), _mm_shuffle_epi8(sbot, t6), K),
                                                 sr[r % 4]);

                            return B;
                        }

                        __m128i t7 = mm_xor3(_mm_shuffle_epi8(sb1t, t6), _mm_shuffle_epi8(sb1u, t5), K);

                        __m128i t8 = mm_xor3(_mm_shuffle_epi8(sb2t, t6), _mm_shuffle_epi8(sb2u, t5),
                                             _mm_shuffle_epi8(t7, mc_forward[r % 4]));

                        B = mm_xor3(_mm_shuffle_epi8(t8, mc_forward[r % 4]), _mm_shuffle_epi8(t7, mc_backward[r % 4]),
                                    t8);
                    }
                }

                BOOST_ATTRIBUTE_TARGET("ssse3") __m128i aes_ssse3_decrypt(__m128i B, const __m128i *keys, size_t rounds) {
                    const __m128i k_dipt1 = _mm_set_epi32(0x154A411E, 0x114E451A, 0x0F505B04, 0x0B545F00);
                    const __m128i k_dipt2 = _mm_set_epi32(0x12771772, 0xF491F194, 0x86E383E6, 0x60056500);

                    const __m128i sb9u = _mm_set_epi32(0xCAD51F50, 0x4F994CC9, 0x851C0353, 0x9A86D600);
                    const __m128i sb9t = _mm_set_epi32(0x725E2C9E, 0xB2FBA565, 0xC03B1789, 0xECD74900);

                    const __m128i sbeu = _mm_set_epi32(0x22426004, 0x64B4F6B0, 0x46F29296, 0x26D4D000);
                    const __m128i sbet = _mm_set_epi32(0x9467F36B, 0x98593E32, 0x0C55A6CD, 0xFFAAC100);

                    const __m128i sbdu = _mm_set_epi32(0xF56E9B13, 0x882A4439, 0x7D57CCDF, 0xE6B1A200);
                    const __m128i sbdt = _mm_set_epi32(0x2931180D, 0x15DEEFD3, 0x3CE2FAF7, 0x24C6CB00);

                    const __m128i sbbu = _mm_set_epi32(0x602646F6, 0xB0F2D404, 0xD0226492, 0x96B44200);
                    const __m128i sbbt = _mm_set_epi32(0xF3FF0C3E, 0x3255AA6B, 0xC19498A6, 0xCD596700);

                    __m128i mc = mc_forward[3];

                    __m128i t = _mm_shuffle_epi8(k_dipt2, _mm_srli_epi32(_mm_andnot_si128(low_nibs, B), 4));

                    B = mm_xor3(t, _mm_loadu_si128(keys), _mm_shuffle_epi8(k_dipt1, _mm_and_si128(B, low_nibs)));

                    for (size_t r = 1;; ++r) {
                        const __m128i K = _mm_loadu_si128(keys + r);

                        t = _mm_srli_epi32(_mm_andnot_si128(low_nibs, B), 4);

                        B = _mm_and_si128(low_nibs, B);

                        __m128i t2 = _mm_shuffle_epi8(k_inv2, B);

                        B = _mm_xor_si128(B, t);

                        __m128i t3 = _mm_xor_si128(t2, _mm_shuffle_epi8(k_inv1, t));
                        __m128i t4 = _mm_xor_si128(t2, _mm_shuffle_epi8(k_inv1, B));
                        __m128i t5 = _mm_xor_si128(B, _mm_shuffle_epi8(k_inv1, t3));
                        __m128i t6 = _mm_xor_si128(t, _mm_shuffle_epi8(k_inv1, t4));

                        if (r == rounds) {
                            const __m128i sbou = _mm_set_epi32(0xC7AA6DB9, 0xD4943E2D, 0x1387EA53, 0x7EF94000);
                            const __m128i sbot = _mm_set_epi32(0xCA4B8159, 0xD8C58E9C, 0x12D7560F, 0x93441D00);

                            __m128i x = _mm_shuffle_epi8(sbou, t5);
                            __m128i y = _mm_shuffle_epi8(sbot, t6);
                            x = _mm_xor_si128(x, K);
                            x = _mm_xor_si128(x, y);

                            const uint32_t which_sr = ((((rounds - 1) << 4) ^ 48) & 48) / 16;
                            return _mm_shuffle_epi8(x, sr[which_sr]);
                        }

                        __m128i t8 =
                            _mm_xor_si128(_mm_shuffle_epi8(sb9t, t6), _mm_xor_si128(_mm_shuffle_epi8(sb9u, t5), K));

                        __m128i t9 =
                            mm_xor3(_mm_shuffle_epi8(t8, mc), _mm_shuffle_epi8(sbdu, t5), _mm_shuffle_epi8(sbdt, t6));

                        __m128i t12 = _mm_xor_si128(_mm_xor_si128(_mm_shuffle_epi8(t9, mc), _mm_shuffle_epi8(sbbu, t5)),
                                                    _mm_shuffle_epi8(sbbt, t6));

                        B = _mm_xor_si128(_mm_xor_si128(_mm_shuffle_epi8(t12, mc), _mm_shuffle_epi8(sbeu, t5)),
                                          _mm_shuffle_epi8(sbet, t6));

                        mc = _mm_alignr_epi8(mc, mc, 12);
                    }
                }

                template<std::size_t KeyBitsImpl, std::size_t BlockBitsImpl, typename PolicyType>
                class basic_rijndael_ssse3_impl {
                    BOOST_STATIC_ASSERT(BlockBitsImpl == 128);
                };

                template<std::size_t KeyBitsImpl, std::size_t BlockBitsImpl, typename PolicyType>
                class rijndael_ssse3_impl : public basic_rijndael_ssse3_impl<KeyBitsImpl, BlockBitsImpl, PolicyType> {
                    BOOST_STATIC_ASSERT(BlockBitsImpl == 128);
                };

                template<std::size_t KeyBitsImpl, typename PolicyType>
                class basic_rijndael_ssse3_impl<KeyBitsImpl, 128, PolicyType> {
                protected:
                    typedef PolicyType policy_type;
                    typedef typename policy_type::block_type block_type;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    BOOST_STATIC_ASSERT(PolicyType::key_bits == KeyBitsImpl);
                    BOOST_STATIC_ASSERT(PolicyType::block_bits == 128);

                public:
                    static block_type encrypt_block(const block_type &plaintext,
                                                    const key_schedule_type &encryption_key) {
                        block_type out = {0};

                        const __m128i *in_mm = reinterpret_cast<const __m128i *>(plaintext.data());
                        __m128i *out_mm = reinterpret_cast<__m128i *>(out.data());

                        const __m128i *keys = reinterpret_cast<const __m128i *>(encryption_key.data());

                        using namespace nil::crypto3::detail;
//                        poison(plaintext.data(), policy_type::block_bytes);

                        __m128i B = _mm_loadu_si128(in_mm);
                        _mm_storeu_si128(out_mm, detail::aes_ssse3_encrypt(B, keys, policy_type::rounds));

//                        unpoison(plaintext.data(), policy_type::block_bytes);
//                        unpoison(out.data(), policy_type::block_bytes);

                        return out;
                    }

                    static block_type decrypt_block(const block_type &plaintext,
                                                    const key_schedule_type &decryption_key) {
                        block_type out = {0};

                        const __m128i *in_mm = reinterpret_cast<const __m128i *>(plaintext.data());
                        __m128i *out_mm = reinterpret_cast<__m128i *>(out.data());

                        const __m128i *keys = reinterpret_cast<const __m128i *>(decryption_key.data());

                        using namespace nil::crypto3::detail;
//                        poison(plaintext.data(), policy_type::block_bytes);

                        __m128i B = _mm_loadu_si128(in_mm);
                        _mm_storeu_si128(out_mm, detail::aes_ssse3_decrypt(B, keys, policy_type::rounds));

//                        unpoison(plaintext.data(), policy_type::block_bytes);
//                        unpoison(out.data(), policy_type::block_bytes);

                        return out;
                    }
                };

                template<typename PolicyType>
                class rijndael_ssse3_impl<128, 128, PolicyType>
                    : public basic_rijndael_ssse3_impl<128, 128, PolicyType> {
                protected:
                    typedef typename basic_rijndael_ssse3_impl<128, 128, PolicyType>::policy_type policy_type;

                    typedef typename policy_type::block_type block_type;
                    typedef typename policy_type::key_type key_type;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                public:
                    static void schedule_key(const key_type &input_key, key_schedule_type &encryption_key,
                                             key_schedule_type &decryption_key) {
                        __m128i rcon = _mm_set_epi32(0x702A9808, 0x4D7C7D81, 0x1F8391B9, 0xAF9DEEB6);

                        __m128i key = _mm_loadu_si128(reinterpret_cast<const __m128i *>(input_key.data()));

                        __m128i *encryption_key_mm = reinterpret_cast<__m128i *>(encryption_key.data());
                        __m128i *decryption_key_mm = reinterpret_cast<__m128i *>(decryption_key.data());

                        _mm_storeu_si128(decryption_key_mm + policy_type::rounds, _mm_shuffle_epi8(key, detail::sr[2]));

                        key = detail::aes_schedule_transform(key, detail::k_ipt1, detail::k_ipt2);

                        _mm_storeu_si128(encryption_key_mm, key);


                        for (size_t i = 1; i != policy_type::rounds; ++i) {
                            key = detail::aes_schedule_round(&rcon, key, key);

                            _mm_storeu_si128(encryption_key_mm + i, detail::aes_schedule_mangle(key, (12 - i) % 4));

                            _mm_storeu_si128(decryption_key_mm + (policy_type::rounds - i),
                                             detail::aes_schedule_mangle_dec(key, (10 - i) % 4));
                        }

                        key = detail::aes_schedule_round(&rcon, key, key);
                        _mm_storeu_si128(encryption_key_mm + policy_type::rounds,
                                         detail::aes_schedule_mangle_last(key, 2));
                        _mm_storeu_si128(decryption_key_mm, detail::aes_schedule_mangle_last_dec(key));
                    }
                };

                template<typename PolicyType>
                class rijndael_ssse3_impl<192, 128, PolicyType>
                    : public basic_rijndael_ssse3_impl<192, 128, PolicyType> {
                protected:
                    typedef typename basic_rijndael_ssse3_impl<192, 128, PolicyType>::policy_type policy_type;

                    typedef typename policy_type::block_type block_type;
                    typedef typename policy_type::key_type key_type;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                public:
                    static void schedule_key(const key_type &input_key, key_schedule_type &encryption_key,
                                             key_schedule_type &decryption_key) {
                        __m128i rcon = _mm_set_epi32(0x702A9808, 0x4D7C7D81, 0x1F8391B9, 0xAF9DEEB6);

                        __m128i *encryption_key_mm = reinterpret_cast<__m128i *>(encryption_key.data());
                        __m128i *decryption_key_mm = reinterpret_cast<__m128i *>(decryption_key.data());

                        __m128i key1 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(input_key.data()));
                        __m128i key2 = _mm_loadu_si128(reinterpret_cast<const __m128i *>((input_key.data() + 8)));

                        _mm_storeu_si128(decryption_key_mm + policy_type::rounds,
                                         _mm_shuffle_epi8(key1, detail::sr[0]));

                        key1 = detail::aes_schedule_transform(key1, detail::k_ipt1, detail::k_ipt2);
                        key2 = detail::aes_schedule_transform(key2, detail::k_ipt1, detail::k_ipt2);

                        _mm_storeu_si128(encryption_key_mm + 0, key1);

                        // key2 with 8 high bytes masked off
                        __m128i t = _mm_slli_si128(_mm_srli_si128(key2, 8), 8);


                        for (size_t i = 0; i != 4; ++i) {
                            key2 = detail::aes_schedule_round(&rcon, key2, key1);

                            _mm_storeu_si128(encryption_key_mm + 3 * i + 1,
                                             detail::aes_schedule_mangle(_mm_alignr_epi8(key2, t, 8), (i + 3) % 4));
                            _mm_storeu_si128(decryption_key_mm + 11 - 3 * i,
                                             detail::aes_schedule_mangle_dec(_mm_alignr_epi8(key2, t, 8), (i + 3) % 4));

                            t = detail::aes_schedule_192_smear(key2, t);

                            _mm_storeu_si128(encryption_key_mm + 3 * i + 2,
                                             detail::aes_schedule_mangle(t, (i + 2) % 4));
                            _mm_storeu_si128(decryption_key_mm + 10 - 3 * i,
                                             detail::aes_schedule_mangle_dec(t, (i + 2) % 4));

                            key2 = detail::aes_schedule_round(&rcon, t, key2);

                            if (i == 3) {
                                _mm_storeu_si128(encryption_key_mm + 3 * i + 3,
                                                 detail::aes_schedule_mangle_last(key2, (i + 1) % 4));
                                _mm_storeu_si128(decryption_key_mm + 9 - 3 * i,
                                                 detail::aes_schedule_mangle_last_dec(key2));
                            } else {
                                _mm_storeu_si128(encryption_key_mm + 3 * i + 3,
                                                 detail::aes_schedule_mangle(key2, (i + 1) % 4));
                                _mm_storeu_si128(decryption_key_mm + 9 - 3 * i,
                                                 detail::aes_schedule_mangle_dec(key2, (i + 1) % 4));
                            }

                            key1 = key2;
                            key2 = detail::aes_schedule_192_smear(key2, _mm_slli_si128(_mm_srli_si128(t, 8), 8));
                            t = _mm_slli_si128(_mm_srli_si128(key2, 8), 8);
                        }
                    }
                };

                template<typename PolicyType>
                class rijndael_ssse3_impl<256, 128, PolicyType>
                    : public basic_rijndael_ssse3_impl<256, 128, PolicyType> {
                protected:
                    typedef typename basic_rijndael_ssse3_impl<256, 128, PolicyType>::policy_type policy_type;

                    typedef typename policy_type::block_type block_type;
                    typedef typename policy_type::key_type key_type;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                public:
                    static void schedule_key(const key_type &input_key, key_schedule_type &encryption_key,
                                             key_schedule_type &decryption_key) {
                        __m128i rcon = _mm_set_epi32(0x702A9808, 0x4D7C7D81, 0x1F8391B9, 0xAF9DEEB6);

                        __m128i *encryption_key_mm = reinterpret_cast<__m128i *>(encryption_key.data());
                        __m128i *decryption_key_mm = reinterpret_cast<__m128i *>(decryption_key.data());

                        __m128i key1 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(input_key.data()));
                        __m128i key2 = _mm_loadu_si128(reinterpret_cast<const __m128i *>((input_key.data() + 16)));

                        _mm_storeu_si128(decryption_key_mm + policy_type::rounds,
                                         _mm_shuffle_epi8(key1, detail::sr[2]));

                        key1 = detail::aes_schedule_transform(key1, detail::k_ipt1, detail::k_ipt2);
                        key2 = detail::aes_schedule_transform(key2, detail::k_ipt1, detail::k_ipt2);

                        _mm_storeu_si128(encryption_key_mm + 0, key1);
                        _mm_storeu_si128(encryption_key_mm + 1, detail::aes_schedule_mangle(key2, 3));

                        _mm_storeu_si128(decryption_key_mm + 13, detail::aes_schedule_mangle_dec(key2, 1));


                        for (size_t i = 2; i != 14; i += 2) {
                            __m128i k_t = key2;
                            key1 = key2 = detail::aes_schedule_round(&rcon, key2, key1);

                            _mm_storeu_si128(encryption_key_mm + i, detail::aes_schedule_mangle(key2, i % 4));
                            _mm_storeu_si128(decryption_key_mm + (14 - i),
                                             detail::aes_schedule_mangle_dec(key2, (i + 2) % 4));

                            key2 = detail::aes_schedule_round(nullptr, _mm_shuffle_epi32(key2, 0xFF), k_t);
                            _mm_storeu_si128(encryption_key_mm + i + 1, detail::aes_schedule_mangle(key2, (i - 1) % 4));
                            _mm_storeu_si128(decryption_key_mm + (13 - i),
                                             detail::aes_schedule_mangle_dec(key2, (i + 1) % 4));
                        }

                        key2 = detail::aes_schedule_round(&rcon, key2, key1);

                        _mm_storeu_si128(encryption_key_mm + 14, detail::aes_schedule_mangle_last(key2, 2));
                        _mm_storeu_si128(decryption_key_mm + 0, detail::aes_schedule_mangle_last_dec(key2));
                    }
                };

                /*!
                 * @endcond
                 */
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SSSE3_RIJNDAEL_IMPL_HPP
