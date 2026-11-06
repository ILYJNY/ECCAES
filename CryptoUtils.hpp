#pragma once
#include <vector>
#include <array>
#include <string>
#include <iomanip>
#include <sstream>
#include <boost/multiprecision/cpp_int.hpp>

using Byte = uint8_t;
using namespace boost::multiprecision;

/* ================= 모듈러 연산 및 수학 도구 ================= */
inline cpp_int mod(cpp_int a, cpp_int m) { return (a % m + m) % m; }

inline cpp_int modpow(cpp_int base, cpp_int exp, cpp_int mod_val) {
    cpp_int res = 1;
    base = base % mod_val;
    while (exp > 0) {
        if (exp % 2 == 1) res = (res * base) % mod_val;
        base = (base * base) % mod_val;
        exp /= 2;
    }
    return res;
}

inline cpp_int inv(cpp_int a, cpp_int m) {
    cpp_int t = 0, newt = 1, r = m, newr = mod(a, m);
    while (newr != 0) {
        cpp_int q = r / newr;
        std::tie(t, newt) = std::make_pair(newt, t - q * newt);
        std::tie(r, newr) = std::make_pair(newr, r - q * newr);
    }
    return mod(t, m);
}

// --- [공통 헥사 변환 유틸리티] ---
inline std::string bytes_to_hex(const std::vector<Byte>& data) {
    std::stringstream ss;
    for (auto b : data) ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return ss.str();
}

inline std::vector<Byte> hex_to_bytes(const std::string& hex) {
    std::vector<Byte> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        bytes.push_back(std::stoi(hex.substr(i, 2), nullptr, 16));
    }
    return bytes;
}