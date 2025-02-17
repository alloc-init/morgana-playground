#ifndef OTHERFILE_H
#define OTHERFILE_H
#include <ostream>
#include <sstream>

#include <nil/crypto3/algebra/curves/bls12.hpp>

using namespace nil::crypto3;

namespace morgana {
    namespace playground {
        template<typename FieldParams>
        void print_field_element(std::ostream &os, const typename algebra::fields::detail::element_fp<FieldParams> &e) {
            os << std::hex << e.data << std::endl;
        }
    }
}

#endif //OTHERFILE_H
