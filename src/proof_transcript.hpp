#ifndef PROOF_TRANSCRIPT_HPP
#define PROOF_TRANSCRIPT_HPP
#include <cstdint>
#include <ranges>
#include <vector>
#include <nil/crypto3/algebra/type_traits.hpp>

namespace morgana {
    namespace playground {
        namespace transcript {
            using ProofAtom = uint8_t;
            using Proof = std::vector<ProofAtom>;

            template <typename Iter>
            concept ProofIterator = std::forward_iterator<Iter> && std::same_as<typename std::iterator_traits<Iter>::value_type, ProofAtom>;

            template <typename Range>
            concept ProofRange = requires(Range r){
                {r.begin()} -> ProofIterator<>;
                {r.end()} -> ProofIterator<>;
            };

            template <typename Element>
            concept Field = algebra::is_field_element<Element>::value;

            template <typename Element>
            concept Group = algebra::is_group_element<Element>::value;

            template <typename Element>
            concept FieldOrGroup = Field<Element> || Group<Element>;

            template <typename Element>
            concept HasFieldOrGroupValueType = FieldOrGroup<typename Element::value_type>;

            template <typename Element>
            concept Challenge = HasFieldOrGroupValueType<Element> && std::unsigned_integral<typeof(Element::modulus_bits)>;

            enum TranscriptMode {
              Prover,
              Verifier,
            };

            template<TranscriptMode mode, typename Backend>
            class ProofTranscript;

            template<typename Backend>
            class ProofTranscript<Prover, Backend> {
                Proof proof {};
                Backend transcript {};
                bool ended = false;

            protected:
                template<ProofRange InputRange>
                explicit ProofTranscript(const InputRange &r) : transcript(r) {}

            public:
                template<typename TBackend, ProofRange InputRange>
                friend ProofTranscript<Prover, TBackend> start_prover(const InputRange &r);

                Proof end() {
                    this->ended = true;
                    return std::move(this->proof);
                }

                template<Challenge FieldType>
                typename FieldType::value_type challenge() {
                    return this->transcript.template challenge<FieldType>();
                }

                template<typename FieldType, std::size_t N>
                std::array<typename FieldType::value_type, N> challenges() {
                    return this->transcript.challenges();
                }

                template<ProofIterator InputIterator>
                void write_proof_iterators(InputIterator first, InputIterator last) {
                    BOOST_ASSERT(!this->ended);
                    this->transcript(first, last);
                    this->proof.insert(this->proof.end(), first, last);
                }

                template<ProofRange InputRange>
                void write_proof_range(const InputRange &values) {
                    this->write_proof_iterators(values.begin(), values.end());
                }

                template<FieldOrGroup Element>
                void write(const Element &value) {
                    nil::marshalling::status_type status;
                    const std::vector<std::uint8_t> byte_data =
                                nil::marshalling::pack<nil::marshalling::option::big_endian>(value, status);
                    BOOST_ASSERT(status == nil::marshalling::status_type::success);
                    this->write_proof_range(byte_data);
                }

                ~ProofTranscript() {
                    BOOST_ASSERT(this->ended);
                }
            };

            template<typename Backend = zk::transcript::fiat_shamir_heuristic_sequential<hashes::keccak_1600<>>, ProofRange InputRange>
            ProofTranscript<Prover, Backend> start_prover(const InputRange &r) {
                return ProofTranscript<Prover, Backend>(r);
            }


            template<typename Backend>
            class ProofTranscript<Verifier, Backend> {
                size_t read_proof_len = 0;
                Proof proof;
                Backend transcript;
                bool ended = false;

            protected:
                template<ProofRange InputRange>
                explicit ProofTranscript(const InputRange &r, Proof &&proof) : proof(std::move(proof)), transcript(r) {}

            public:
                template<typename TBackend, ProofRange InputRange>
                friend ProofTranscript<Verifier, TBackend> start_verifier(const InputRange &r, Proof proof);

                Proof end() {
                    this->ended = true;
                    return std::move(this->proof);
                }

                template<Challenge FieldType>
                typename FieldType::value_type challenge() {
                    return this->transcript.template challenge<FieldType>();
                }

                template<typename FieldType, std::size_t N>
                std::array<typename FieldType::value_type, N> challenges() {
                    return this->transcript.challenges();
                }

                std::vector<uint8_t> read_proof_raw(size_t len) {
                    auto first = this->proof.begin() + this->read_proof_len;
                    this->read_proof_len += len;
                    auto last = this->proof.begin() + this->read_proof_len;
                    this->transcript(first, last);
                    return std::vector<uint8_t>(first, last);
                }

                template<size_t N>
                std::array<uint8_t, N> read_proof_raw() {
                    auto first = this->proof.begin() + this->read_proof_len;
                    this->read_proof_len += N;
                    auto last = this->proof.begin() + this->read_proof_len;
                    this->transcript(first, last);
                    std::array<uint8_t, N> result {};
                    for (auto &r : result) {
                        r = *first++;
                    }
                    return result;
                }

                template<FieldOrGroup T>
                T read() {
                    using marshalling_type = typename nil::marshalling::is_compatible<T>::template type<nil::marshalling::option::big_endian>;
                    auto marshalled = this->read_proof_raw(marshalling_type::length());
                    nil::marshalling::status_type status;
                    T t = nil::marshalling::pack<nil::marshalling::option::big_endian>(marshalled, status);
                    BOOST_ASSERT(status == nil::marshalling::status_type::success);
                    return t;
                }

                ~ProofTranscript() {
                    BOOST_ASSERT(this->ended);
                }
            };

            template<typename Backend = zk::transcript::fiat_shamir_heuristic_sequential<hashes::keccak_1600<>>, ProofRange InputRange>
            ProofTranscript<Verifier, Backend> start_verifier(const InputRange &r, Proof proof) {
                auto proof_transcript = ProofTranscript<Verifier, Backend>(r, std::move(proof));
                return proof_transcript;
            }

        }
    }
}

#endif //PROOF_TRANSCRIPT_HPP
