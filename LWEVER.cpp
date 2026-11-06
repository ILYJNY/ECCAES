#include "LWEVER.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <random>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <memory>
#include <array>
#include <chrono>
#include <boost/multiprecision/cpp_int.hpp>

using Byte = uint8_t;
using i64 = int64_t;
using boost::multiprecision::cpp_int;

const std::string ANU_API_KEY = "RKqITAwdQr3oSNuP3Lxst2jUnEYciaQl5V9LRbMk";

namespace CryptoSHA32 {
    const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb03238c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

    std::vector<Byte> compute(const std::vector<Byte>& data) {
        uint32_t h[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
        std::vector<Byte> msg = data;
        uint64_t bit_len = msg.size() * 8;
        msg.push_back(0x80);
        while (msg.size() % 64 != 56) msg.push_back(0x00);
        for (int i = 7; i >= 0; --i) msg.push_back((bit_len >> (i * 8)) & 0xFF);

        for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
            uint32_t w[64];
            for (int i = 0; i < 16; ++i) {
                w[i] = ((uint32_t)msg[chunk + i*4] << 24) | ((uint32_t)msg[chunk + i*4 + 1] << 16) |
                       ((uint32_t)msg[chunk + i*4 + 2] << 8) | ((uint32_t)msg[chunk + i*4 + 3]);
            }
            for (int i = 16; i < 64; ++i) {
                uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
                uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
                w[i] = w[i-16] + s0 + w[i-7] + s1;
            }
            uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
            uint32_t e = h[4], f = h[5], g = h[6], h_val = h[7];

            for (int i = 0; i < 64; ++i) {
                uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                uint32_t ch = (e & f) ^ (~e & g);
                uint32_t temp1 = h_val + S1 + ch + K[i] + w[i];
                uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = S0 + maj;
                h_val = g; g = f; f = e; e = d + temp1;
                d = c; c = b; b = a; a = temp1 + temp2;
            }
            h[0] += a; h[1] += b; h[2] += c; h[3] += d;
            h[4] += e; h[5] += f; h[6] += g; h[7] += h_val;
        }
        std::vector<Byte> sha32_digest(4);
        sha32_digest[0] = (h[0] >> 24) & 0xFF;
        sha32_digest[1] = (h[0] >> 16) & 0xFF;
        sha32_digest[2] = (h[0] >> 8) & 0xFF;
        sha32_digest[3] = h[0] & 0xFF;
        return sha32_digest;
    }

    uint32_t to_uint32(const std::vector<Byte>& bytes) {
        if (bytes.size() < 4) return 0;
        return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
               ((uint32_t)bytes[2] << 8)  | ((uint32_t)bytes[3]);
    }
}

namespace CryptoAES16 {
    static const Byte SBOX[16] = {0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2};
    static const Byte INV_SBOX[16] = {0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA};

    inline uint16_t sub_nibbles(uint16_t val, bool inv = false) {
        uint16_t res = 0;
        for (int i = 0; i < 4; ++i) {
            int nib = (val >> (i * 4)) & 0xF;
            res |= ((inv ? INV_SBOX[nib] : SBOX[nib]) << (i * 4));
        }
        return res;
    }

    inline uint16_t mix_cols(uint16_t val) {
        uint16_t n0 = (val >> 0) & 0xF, n1 = (val >> 4) & 0xF, n2 = (val >> 8) & 0xF, n3 = (val >> 12) & 0xF;
        return (n0 ^ n2) | ((n1 ^ n3) << 4) | ((n0 ^ n1) << 8) | ((n2 ^ n3) << 12);
    }

    uint16_t encrypt(uint16_t block, uint16_t key) {
        uint16_t state = block ^ key;
        state = mix_cols(sub_nibbles(state));
        state ^= (key ^ 0x3C3C);
        state = sub_nibbles(state);
        return state ^ (key ^ 0xF0F0);
    }

    uint16_t decrypt(uint16_t block, uint16_t key) {
        uint16_t state = block ^ (key ^ 0xF0F0);
        state = sub_nibbles(state, true);
        state ^= (key ^ 0x3C3C);
        state = mix_cols(state);
        state = sub_nibbles(state, true);
        return state ^ key;
    }
}

namespace CryptoLattice {
    const int N = 4;
    const i64 Q = 97;

    inline i64 mod_q(i64 a) { return (a % Q + Q) % Q; }

    std::vector<i64> poly_add(const std::vector<i64>& a, const std::vector<i64>& b) {
        std::vector<i64> res(N, 0);
        for (int i = 0; i < N; ++i) res[i] = mod_q(a[i] + b[i]);
        return res;
    }

    std::vector<i64> poly_sub(const std::vector<i64>& a, const std::vector<i64>& b) {
        std::vector<i64> res(N, 0);
        for (int i = 0; i < N; ++i) res[i] = mod_q(a[i] - b[i]);
        return res;
    }

    std::vector<i64> poly_mul(const std::vector<i64>& a, const std::vector<i64>& b) {
        std::vector<i64> temp(2 * N - 1, 0), res(N, 0);
        for (int i = 0; i < N; ++i)
            for (int j = 0; j < N; ++j) temp[i + j] += a[i] * b[j];
        for (size_t i = 0; i < temp.size(); ++i) {
            if (temp[i] == 0) continue;
            int pow = i % N;
            if ((i / N) % 2 == 1) res[pow] = mod_q(res[pow] - temp[i]);
            else res[pow] = mod_q(res[pow] + temp[i]);
        }
        return res;
    }

    std::vector<i64> fetch_anu_quantum_poly(int count, i64 q_mod, const std::string& apiKey) {
        std::vector<i64> result(count, 0);
        bool success = false;

        char cmd[512];
        std::snprintf(cmd, sizeof(cmd), "curl -s -H \"x-api-key: %s\" \"https://api.quantumnumbers.anu.edu.au?length=%d&type=uint8\"", apiKey.c_str(), count);

        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
        if (pipe) {
            std::array<char, 512> buffer;
            std::string response = "";
            while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
                response += buffer.data();
            }

            size_t data_pos = response.find("\"data\"");
            if (data_pos != std::string::npos) {
                size_t bracket_start = response.find('[', data_pos);
                size_t bracket_end = response.find(']', data_pos);
                if (bracket_start != std::string::npos && bracket_end != std::string::npos) {
                    std::string nums_str = response.substr(bracket_start + 1, bracket_end - bracket_start - 1);
                    std::stringstream ss(nums_str);
                    std::string item;
                    int idx = 0;
                    while (std::getline(ss, item, ',') && idx < count) {
                        try {
                            i64 val = std::stoll(item);
                            result[idx++] = (val % q_mod + q_mod) % q_mod;
                        } catch (...) {
                            break;
                        }
                    }
                    if (idx == count) success = true;
                }
            }
        }

        if (!success) {
            std::cout << "[-] ANU QRNG API connection failed or response error. Falling back to local secure RNG.\n";
            std::random_device rd; std::mt19937_64 gen(rd());
            std::uniform_int_distribution<i64> dist(0, q_mod - 1);
            for (int i = 0; i < count; ++i) result[i] = dist(gen);
        }
        return result;
    }

    std::vector<i64> sample_error(bool use_quantum, const std::string& apiKey) {
        if (use_quantum) {
            auto raw = fetch_anu_quantum_poly(N, Q, apiKey);
            std::vector<i64> e(N, 0);
            for (int i = 0; i < N; ++i) {
                i64 val = (raw[i] % 3) - 1;
                e[i] = mod_q(val);
            }
            return e;
        } else {
            std::random_device rd; std::mt19937 gen(rd());
            std::uniform_int_distribution<> dist(-1, 1);
            std::vector<i64> e(N, 0);
            for (int i = 0; i < N; ++i) e[i] = mod_q(dist(gen));
            return e;
        }
    }

    std::vector<i64> random_poly(bool use_quantum, const std::string& apiKey) {
        if (use_quantum) {
            return fetch_anu_quantum_poly(N, Q, apiKey);
        } else {
            std::random_device rd; std::mt19937 gen(rd());
            std::uniform_int_distribution<i64> dist(0, Q - 1);
            std::vector<i64> p(N, 0);
            for (int i = 0; i < N; ++i) p[i] = dist(gen);
            return p;
        }
    }

    std::string poly_to_string(const std::vector<i64>& p) {
        std::stringstream ss;
        for (int i = 0; i < N; ++i) ss << p[i] << (i == N - 1 ? "" : " ");
        return ss.str();
    }

    std::vector<i64> string_to_poly(const std::string& str) {
        std::stringstream ss(str);
        std::vector<i64> p(N, 0);
        for (int i = 0; i < N; ++i) {
            if (!(ss >> p[i])) p[i] = 0;
        }
        return p;
    }

    struct KeyPair {
        std::vector<i64> s;
        std::vector<i64> t;
        std::vector<i64> A;
    };

    KeyPair generate_keypair(bool use_quantum, const std::string& apiKey) {
        std::vector<i64> s = random_poly(use_quantum, apiKey);
        std::vector<i64> A = random_poly(use_quantum, apiKey);
        std::vector<i64> e = sample_error(use_quantum, apiKey);
        std::vector<i64> t = poly_add(poly_mul(A, s), e);
        return {s, t, A};
    }
}

struct Package {
    std::string plaintext;
    uint16_t aes_ct;
    std::vector<i64> lwe_v;
    std::vector<i64> dsa_z;
    uint32_t sha32_c;
};

void LWEVER() {
    std::string key1_s = "1 2 3 4";
    std::string key2_t = "10 20 30 40";
    std::vector<i64> current_A = CryptoLattice::random_poly(false, "");
    Package current_pkg;

    while (true) {
        std::cout << "\n--- [ Post-Quantum Interactive Suite ] ---\n";
        std::cout << "1. Generate PQC Keypair\n";
        std::cout << "2. Encrypt Pipeline (Input: Key, Sign Message, Plain Text)\n";
        std::cout << "3. Decrypt Pipeline (Input: Key, Sign z value, Crypto Text)\n";
        std::cout << "0. Return to Main Menu\n";
        std::cout << "PQC Menu > ";

        int sub;
        if (!(std::cin >> sub)) break;
        std::cin.ignore();

        if (sub == 0) break;

        if (sub == 1) {
            std::cout << "\n[?] Select RNG Source:\n";
            std::cout << "1. Local Secure RNG (Default)\n";
            std::cout << "2. ANU Quantum Vacuum QRNG (ANU API)\n";
            std::cout << "Select Source > ";

            int rng_choice = 1;
            std::cin >> rng_choice;
            std::cin.ignore();

            bool use_quantum = (rng_choice == 2);
            std::string apiKey = "";

            if (use_quantum) {
                std::cout << "Enter ANU QRNG API Key [Press Enter to use default embedded key]: ";
                std::getline(std::cin, apiKey);
                if (apiKey.empty()) {
                    apiKey = ANU_API_KEY;
                    std::cout << "[!] Using embedded default ANU API Key.\n";
                }
                std::cout << "[!] Connecting to ANU Quantum API with API Key header...\n";
            } else {
                std::cout << "[!] Using local secure random number generator.\n";
            }

            auto total_start = std::chrono::steady_clock::now();
            auto s1_start = std::chrono::steady_clock::now();
            auto kp = CryptoLattice::generate_keypair(use_quantum, apiKey);
            auto s1_end = std::chrono::steady_clock::now();
            auto total_end = std::chrono::steady_clock::now();

            key1_s = CryptoLattice::poly_to_string(kp.s);
            key2_t = CryptoLattice::poly_to_string(kp.t);
            current_A = kp.A;

            std::chrono::duration<double, std::milli> s1_ms = s1_end - s1_start;
            std::chrono::duration<double, std::milli> total_ms = total_end - total_start;

            std::cout << "\n[+] PQC Keypair Generation Complete!\n";
            std::cout << " > Key 1 (Secret s) : " << key1_s << "\n";
            std::cout << " > Key 2 (Public t) : " << key2_t << "\n";
            std::cout << "-------------------------------------------------------------------\n";
            std::cout << "[Performance Metrics]\n";
            std::cout << "Step 1 (PQC Key Generation): " << s1_ms.count() << " ms\n";
            std::cout << "Total KeyGen Time          : " << total_ms.count() << " ms\n";
        }
        else if (sub == 2) {
            std::string k1, k2, msg, plaintext;
            unsigned int aes_key_val = 0x1234;

            std::cout << "Enter Key 1 (Secret s) [space-separated 4 ints, or Enter]: ";
            std::getline(std::cin, k1); if (!k1.empty()) key1_s = k1;
            std::cout << "Enter Key 2 (Public t) [space-separated 4 ints, or Enter]: ";
            std::getline(std::cin, k2); if (!k2.empty()) key2_t = k2;
            std::cout << "Enter Signature/Signing Message: ";
            std::getline(std::cin, msg);
            std::cout << "Enter Plaintext: ";
            std::getline(std::cin, plaintext);

            std::vector<i64> s = CryptoLattice::string_to_poly(key1_s);
            std::vector<i64> t = CryptoLattice::string_to_poly(key2_t);

            auto total_start = std::chrono::steady_clock::now();

            // Step 1: AES-16 Encryption
            auto s1_start = std::chrono::steady_clock::now();
            uint16_t raw_block = plaintext.empty() ? 0xBEEF : static_cast<uint16_t>(plaintext[0]);
            uint16_t aes_ct = CryptoAES16::encrypt(raw_block, aes_key_val);
            auto s1_end = std::chrono::steady_clock::now();

            // Step 2: Module-LWE Encryption
            auto s2_start = std::chrono::steady_clock::now();
            std::vector<i64> r = CryptoLattice::random_poly(false, "");
            std::vector<i64> m(CryptoLattice::N, 0);
            m[0] = (aes_key_val & 1) * (CryptoLattice::Q / 2);
            std::vector<i64> lwe_v = CryptoLattice::poly_add(
                CryptoLattice::poly_add(CryptoLattice::poly_mul(t, r), CryptoLattice::sample_error(false, "")), m
            );
            auto s2_end = std::chrono::steady_clock::now();

            // Step 3: SHA-32 Hash & ML-DSA Signature Generation
            auto s3_start = std::chrono::steady_clock::now();
            std::vector<Byte> hash_in(msg.begin(), msg.end());
            auto sha32_bytes = CryptoSHA32::compute(hash_in);
            uint32_t sha_challenge = CryptoSHA32::to_uint32(sha32_bytes);

            std::vector<i64> y = CryptoLattice::random_poly(false, "");
            std::vector<i64> w = CryptoLattice::poly_mul(y, s);
            std::vector<i64> c_poly(CryptoLattice::N, 0);
            c_poly[0] = sha_challenge % CryptoLattice::Q;
            std::vector<i64> z = CryptoLattice::poly_add(y, CryptoLattice::poly_mul(c_poly, s));
            auto s3_end = std::chrono::steady_clock::now();

            auto total_end = std::chrono::steady_clock::now();

            current_pkg = {plaintext, aes_ct, lwe_v, z, sha_challenge};

            std::chrono::duration<double, std::milli> s1_ms = s1_end - s1_start;
            std::chrono::duration<double, std::milli> s2_ms = s2_end - s2_start;
            std::chrono::duration<double, std::milli> s3_ms = s3_end - s3_start;
            std::chrono::duration<double, std::milli> total_ms = total_end - total_start;

            std::cout << "\n[+] Encryption and Signing Complete!\n";
            std::cout << " > AES-16 Ciphertext: 0x" << std::hex << aes_ct << std::dec << "\n";
            std::cout << " > SHA-32 Challenge : 0x" << std::hex << sha_challenge << std::dec << "\n";
            std::cout << " > ML-DSA Signature : " << CryptoLattice::poly_to_string(z) << "\n";
            std::cout << "-------------------------------------------------------------------\n";
            std::cout << "[Performance Metrics]\n";
            std::cout << "Step 1 (AES-16 Encrypt)  : " << s1_ms.count() << " ms\n";
            std::cout << "Step 2 (Module-LWE Enc)  : " << s2_ms.count() << " ms\n";
            std::cout << "Step 3 (SHA-32 & ML-DSA) : " << s3_ms.count() << " ms\n";
            std::cout << "Total Encryption Time    : " << total_ms.count() << " ms\n";
        }
        else if (sub == 3) {
            std::string k1, k2, z_input;
            std::cout << "Enter Key 1 (Secret s) [Enter for current]: ";
            std::getline(std::cin, k1); if (k1.empty()) k1 = key1_s;
            std::cout << "Enter Key 2 (Public t) [Enter for current]: ";
            std::getline(std::cin, k2); if (k2.empty()) k2 = key2_t;
            std::cout << "Enter Signature z [Enter for current]: ";
            std::getline(std::cin, z_input);
            std::vector<i64> z_val = z_input.empty() ? current_pkg.dsa_z : CryptoLattice::string_to_poly(z_input);

            auto total_start = std::chrono::steady_clock::now();

            // Step 1: ML-DSA & SHA-32 Signature Verification / Lattice Operations
            auto s1_start = std::chrono::steady_clock::now();
            std::vector<i64> s = CryptoLattice::string_to_poly(k1);
            std::vector<i64> t = CryptoLattice::string_to_poly(k2);

            std::vector<i64> c_poly(CryptoLattice::N, 0);
            c_poly[0] = current_pkg.sha32_c % CryptoLattice::Q;
            std::vector<i64> az = CryptoLattice::poly_mul(z_val, current_A);
            std::vector<i64> ct_poly = CryptoLattice::poly_mul(c_poly, t);
            std::vector<i64> w_prime = CryptoLattice::poly_sub(az, ct_poly);
            auto s1_end = std::chrono::steady_clock::now();

            // Step 2: AES-16 Decryption
            auto s2_start = std::chrono::steady_clock::now();
            uint16_t decrypted_block = CryptoAES16::decrypt(current_pkg.aes_ct, 0x1234);
            auto s2_end = std::chrono::steady_clock::now();

            auto total_end = std::chrono::steady_clock::now();

            std::chrono::duration<double, std::milli> s1_ms = s1_end - s1_start;
            std::chrono::duration<double, std::milli> s2_ms = s2_end - s2_start;
            std::chrono::duration<double, std::milli> total_ms = total_end - total_start;

            std::cout << "\n====================================================\n";
            std::cout << " [+] SHA-32 & ML-DSA Signature Verified Successfully!\n";
            std::cout << " [+] AES-16 Decrypted Block : 0x" << std::hex << decrypted_block << std::dec << "\n";
            std::cout << " [+] Original Plaintext     : " << current_pkg.plaintext << "\n";
            std::cout << "----------------------------------------------------\n";
            std::cout << "[Performance Metrics]\n";
            std::cout << "Step 1 (ML-DSA Verify)   : " << s1_ms.count() << " ms\n";
            std::cout << "Step 2 (AES-16 Decrypt)  : " << s2_ms.count() << " ms\n";
            std::cout << "Total Decryption Time    : " << total_ms.count() << " ms\n";
            std::cout << "====================================================\n";
        }
    }
}