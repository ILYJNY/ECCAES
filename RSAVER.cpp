#include <random>
#include <vector>
#include <iomanip>
#include <iostream>
#include <string>
#include <chrono>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#include "CryptoUtils.hpp"
#include "LWEVER.hpp"

using boost::multiprecision::cpp_int;

struct RSA64Key {
    cpp_int n, e, d;
};

static cpp_int generate_prime_32() {
    std::random_device rd;
    std::mt19937_64 eng(rd());
    std::uniform_int_distribution<uint32_t> dist(0x80000000, 0xFFFFFFFF);

    cpp_int p;
    do {
        p = dist(eng);
        boost::multiprecision::bit_set(p, 31);
        boost::multiprecision::bit_set(p, 0);
    } while (!boost::multiprecision::miller_rabin_test(p, 25));
    return p;
}

static RSA64Key generate_rsa64_key() {
    cpp_int p = generate_prime_32();
    cpp_int q = generate_prime_32();
    cpp_int n = p * q;
    cpp_int phi = (p - 1) * (q - 1);
    cpp_int e = 65537;
    cpp_int d = inv(e, phi);
    return {n, e, d};
}

static cpp_int bytes_to_int(const std::vector<Byte>& v) {
    cpp_int res = 0;
    for (auto b : v) res = (res << 8) | b;
    return res;
}

static std::vector<Byte> int_to_bytes(cpp_int val, size_t length) {
    std::vector<Byte> res(length, 0);
    for (int i = length - 1; i >= 0; i--) {
        res[i] = static_cast<Byte>(val & 0xFF);
        val >>= 8;
    }
    return res;
}

static std::vector<Byte> mgf1_sha32(const std::vector<Byte>& seed, size_t maskLen) {
    std::vector<Byte> T;
    uint32_t counter = 0;
    while (T.size() < maskLen) {
        std::vector<Byte> C = {
            static_cast<Byte>((counter >> 24) & 0xFF),
            static_cast<Byte>((counter >> 16) & 0xFF),
            static_cast<Byte>((counter >> 8) & 0xFF),
            static_cast<Byte>(counter & 0xFF)
        };
        std::vector<Byte> toHash = seed;
        toHash.insert(toHash.end(), C.begin(), C.end());
        auto h = CryptoSHA32::compute(toHash);
        T.insert(T.end(), h.begin(), h.end());
        counter++;
    }
    T.resize(maskLen);
    return T;
}

static std::vector<Byte> pss_encode_64(const std::vector<Byte>& mHash, size_t emBits) {
    size_t emLen = (emBits + 7) / 8;
    size_t hLen = 4, sLen = 2;

    std::vector<Byte> salt(sLen);
    std::random_device rd; std::mt19937 eng(rd());
    std::uniform_int_distribution<int> d(0, 255);
    for (size_t i = 0; i < sLen; i++) salt[i] = d(eng);

    std::vector<Byte> M_prime(8, 0x00);
    M_prime.insert(M_prime.end(), mHash.begin(), mHash.end());
    M_prime.insert(M_prime.end(), salt.begin(), salt.end());
    auto H = CryptoSHA32::compute(M_prime);

    std::vector<Byte> DB(emLen - sLen - hLen - 2, 0x00);
    DB.push_back(0x01);
    DB.insert(DB.end(), salt.begin(), salt.end());

    std::vector<Byte> dbMask = mgf1_sha32(H, emLen - hLen - 1);
    std::vector<Byte> maskedDB(DB.size());
    for (size_t i = 0; i < DB.size(); i++) maskedDB[i] = DB[i] ^ dbMask[i];

    Byte mask = (0xFF >> (8 * emLen - emBits));
    maskedDB[0] &= mask;

    std::vector<Byte> EM = maskedDB;
    EM.insert(EM.end(), H.begin(), H.end());
    EM.push_back(0xBC);

    return EM;
}

static bool pss_verify_64(const std::vector<Byte>& mHash, const std::vector<Byte>& EM, size_t emBits) {
    size_t emLen = (emBits + 7) / 8;
    if (EM.size() != emLen) return false;
    size_t hLen = 4, sLen = 2;

    if (EM.back() != 0xBC) return false;

    std::vector<Byte> maskedDB(EM.begin(), EM.begin() + emLen - hLen - 1);
    std::vector<Byte> H(EM.begin() + emLen - hLen - 1, EM.end() - 1);

    Byte mask = (0xFF >> (8 * emLen - emBits));
    if ((maskedDB[0] & ~mask) != 0) return false;

    std::vector<Byte> dbMask = mgf1_sha32(H, emLen - hLen - 1);
    std::vector<Byte> DB(maskedDB.size());
    for (size_t i = 0; i < DB.size(); i++) DB[i] = maskedDB[i] ^ dbMask[i];
    DB[0] &= mask;

    size_t psLen = emLen - sLen - hLen - 2;
    for (size_t i = 0; i < psLen; i++) {
        if (DB[i] != 0x00) return false;
    }
    if (DB[psLen] != 0x01) return false;

    std::vector<Byte> salt(DB.begin() + psLen + 1, DB.end());
    std::vector<Byte> M_prime(8, 0x00);
    M_prime.insert(M_prime.end(), mHash.begin(), mHash.end());
    M_prime.insert(M_prime.end(), salt.begin(), salt.end());

    auto H_calc = CryptoSHA32::compute(M_prime);
    return H == H_calc;
}

void run_rsa_encrypt() {
    std::string msg, custom_recv_n, custom_recv_d, custom_send_n, custom_send_d;
    std::cout << "Plaintext: ";
    std::getline(std::cin, msg);

    std::cout << "Enter Custom Receiver Public Key (n, HEX) [Enter to auto-generate]: ";
    std::getline(std::cin, custom_recv_n);

    RSA64Key recv_key, send_key;
    if (!custom_recv_n.empty()) {
        std::cout << "Enter Custom Receiver Private Key (d, HEX): ";
        std::getline(std::cin, custom_recv_d);
    }

    std::cout << "Enter Custom Sender Public Key (n, HEX) [Enter to auto-generate]: ";
    std::getline(std::cin, custom_send_n);

    if (!custom_send_n.empty()) {
        std::cout << "Enter Custom Sender Private Key (d, HEX): ";
        std::getline(std::cin, custom_send_d);
    }

    auto total_start = std::chrono::steady_clock::now();

    // Step 1: Key Generation / Setup
    auto s1_start = std::chrono::steady_clock::now();
    if (custom_recv_n.empty()) recv_key = generate_rsa64_key();
    else recv_key = {cpp_int("0x" + custom_recv_n), 65537, cpp_int("0x" + custom_recv_d)};

    if (custom_send_n.empty()) send_key = generate_rsa64_key();
    else send_key = {cpp_int("0x" + custom_send_n), 65537, cpp_int("0x" + custom_send_d)};
    auto s1_end = std::chrono::steady_clock::now();

    // Step 2: KEM & AES Encryption
    auto s2_start = std::chrono::steady_clock::now();
    cpp_int R_seed = generate_prime_32();
    cpp_int C_key = modpow(R_seed, recv_key.e, recv_key.n);

    auto seed_bytes = int_to_bytes(R_seed, 4);
    auto h_seed = CryptoSHA32::compute(seed_bytes);
    uint16_t aesKey = (h_seed[0] << 8) | h_seed[1];

    uint16_t block = msg.empty() ? 0x0000 : static_cast<uint16_t>(msg[0]);
    uint16_t ct_block = CryptoAES16::encrypt(block, aesKey);
    auto s2_end = std::chrono::steady_clock::now();

    // Step 3: RSA-PSS Signature Generation
    auto s3_start = std::chrono::steady_clock::now();
    std::vector<Byte> ct_bytes = {static_cast<Byte>(ct_block >> 8), static_cast<Byte>(ct_block & 0xFF)};
    auto mHash = CryptoSHA32::compute(ct_bytes);

    std::vector<Byte> EM = pss_encode_64(mHash, 64 - 1);
    cpp_int em_int = bytes_to_int(EM);
    cpp_int signature = modpow(em_int, send_key.d, send_key.n);
    auto s3_end = std::chrono::steady_clock::now();

    auto total_end = std::chrono::steady_clock::now();

    std::chrono::duration<double, std::milli> s1_ms = s1_end - s1_start;
    std::chrono::duration<double, std::milli> s2_ms = s2_end - s2_start;
    std::chrono::duration<double, std::milli> s3_ms = s3_end - s3_start;
    std::chrono::duration<double, std::milli> total_ms = total_end - total_start;

    std::cout << "\n================ [RSA-64 / SHA-32 / AES-16 Output] ================\n";
    std::cout << "[Receiver Private Key (d, HEX)]\n0x" << std::hex << recv_key.d << "\n\n";
    std::cout << "[Receiver Public Key (n, HEX)]\n0x" << recv_key.n << "\n\n";
    std::cout << "[Sender Public Key (n, HEX)]\n0x" << send_key.n << "\n\n";
    std::cout << "[Encrypted Seed (C_key, HEX)]\n0x" << C_key << "\n\n";
    std::cout << "[AES-16 Ciphertext Block HEX]\n0x" << std::setw(4) << std::setfill('0') << ct_block << "\n\n";
    std::cout << "[RSA-PSS Signature (HEX)]\n0x" << signature << "\n";
    std::cout << "-------------------------------------------------------------------\n";
    std::cout << "[Performance Metrics]\n";
    std::cout << "Step 1 (Key Generation)  : " << s1_ms.count() << " ms\n";
    std::cout << "Step 2 (KEM & AES Enc)   : " << s2_ms.count() << " ms\n";
    std::cout << "Step 3 (RSA-PSS Sign)    : " << s3_ms.count() << " ms\n";
    std::cout << "Total Encryption Time    : " << total_ms.count() << " ms\n";
    std::cout << "===================================================================\n" << std::dec;
}

void run_rsa_decrypt() {
    std::string priv_recv_str, pub_recv_n_str, pub_send_n_str, c_key_str, ct_hex, sig_str;

    std::cout << "Receiver Private Key (d, HEX): "; std::cin >> std::hex >> priv_recv_str;
    std::cout << "Receiver Public Key (n, HEX): "; std::cin >> pub_recv_n_str;
    std::cout << "Sender Public Key (n, HEX): "; std::cin >> pub_send_n_str;
    std::cout << "Encrypted Seed (C_key, HEX): "; std::cin >> c_key_str;
    std::cout << "Ciphertext Block (HEX): "; std::cin >> ct_hex;
    std::cout << "RSA-PSS Signature (HEX): "; std::cin >> sig_str;

    auto total_start = std::chrono::steady_clock::now();

    cpp_int priv_recv("0x" + priv_recv_str);
    cpp_int recv_n("0x" + pub_recv_n_str);
    cpp_int send_n("0x" + pub_send_n_str);
    cpp_int C_key("0x" + c_key_str);
    cpp_int signature("0x" + sig_str);
    uint16_t ct_block = static_cast<uint16_t>(std::stoul(ct_hex, nullptr, 16));

    // Step 1: RSA-PSS Signature Verification
    auto s1_start = std::chrono::steady_clock::now();
    cpp_int em_recovered_int = modpow(signature, 65537, send_n);
    std::vector<Byte> EM = int_to_bytes(em_recovered_int, 8);

    std::vector<Byte> ct_bytes = {static_cast<Byte>(ct_block >> 8), static_cast<Byte>(ct_block & 0xFF)};
    auto mHash = CryptoSHA32::compute(ct_bytes);
    bool ok = pss_verify_64(mHash, EM, 64 - 1);
    auto s1_end = std::chrono::steady_clock::now();

    // Step 2: KEM Decryption & AES Decryption
    auto s2_start = std::chrono::steady_clock::now();
    cpp_int R_seed = modpow(C_key, priv_recv, recv_n);
    auto seed_bytes = int_to_bytes(R_seed, 4);
    auto h_seed = CryptoSHA32::compute(seed_bytes);
    uint16_t aesKey = (h_seed[0] << 8) | h_seed[1];

    uint16_t pt_block = CryptoAES16::decrypt(ct_block, aesKey);
    auto s2_end = std::chrono::steady_clock::now();

    auto total_end = std::chrono::steady_clock::now();

    std::chrono::duration<double, std::milli> s1_ms = s1_end - s1_start;
    std::chrono::duration<double, std::milli> s2_ms = s2_end - s2_start;
    std::chrono::duration<double, std::milli> total_ms = total_end - total_start;

    std::cout << "\n================ [Decryption and Verify Result] ================\n";
    if (ok) {
        std::cout << "[+] PSS Signature Status : VALID (Signature Verification Success)\n";
        std::cout << "[+] Decrypted Plaintext  : " << static_cast<char>(pt_block & 0xFF) << "\n";
    } else {
        std::cout << "[-] PSS Signature Status : INVALID (Signature Verification Failed!)\n";
    }
    std::cout << "-----------------------------------------------------------------\n";
    std::cout << "[Performance Metrics]\n";
    std::cout << "Step 1 (PSS Verify)      : " << s1_ms.count() << " ms\n";
    std::cout << "Step 2 (KEM & AES Dec)   : " << s2_ms.count() << " ms\n";
    std::cout << "Total Decryption Time    : " << total_ms.count() << " ms\n";
    std::cout << "=================================================================\n" << std::dec;
}