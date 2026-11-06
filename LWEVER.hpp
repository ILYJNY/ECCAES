#ifndef LWEVER_HPP
#define LWEVER_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <boost/multiprecision/cpp_int.hpp>

using Byte = uint8_t;
using i64 = int64_t;
using boost::multiprecision::cpp_int;

// ==========================================
// 공통 초경량 암호 모듈 선언 (SHA-32, AES-16)
// ==========================================
namespace CryptoSHA32 {
    std::vector<Byte> compute(const std::vector<Byte>& data);
    uint32_t to_uint32(const std::vector<Byte>& bytes);
}

namespace CryptoAES16 {
    uint16_t encrypt(uint16_t block, uint16_t key);
    uint16_t decrypt(uint16_t block, uint16_t key);
}

// ==========================================
// PQC 인터랙티브 스위트 진입 함수
// ==========================================
void LWEVER();

#endif // LWEVER_HPP