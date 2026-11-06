#include <iostream>
#include <random>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <boost/multiprecision/cpp_int.hpp>
#include "ECCVER.hpp"
#include "CryptoUtils.hpp"
#include "LWEVER.hpp"

using boost::multiprecision::cpp_int;

static const cpp_int P("65537");
static const cpp_int N_ecc("65537");
static const cpp_int Gx("2");
static const cpp_int Gy("3");

struct Point { cpp_int x, y; bool inf = false; };

static cpp_int generateRandom16(const cpp_int& max_val) {
    std::random_device rd;
    std::mt19937 eng(rd());
    std::uniform_int_distribution<uint16_t> dist(1, 0xFFFE);
    return mod(dist(eng), max_val - 1) + 1;
}

static Point add_pt(Point p, Point q) {
    if (p.inf) return q;
    if (q.inf) return p;
    if (p.x == q.x && mod(p.y + q.y, P) == 0) return {0, 0, true};
    cpp_int m;
    if (p.x == q.x && p.y == q.y)
        m = mod((3 * p.x * p.x) * inv(2 * p.y, P), P);
    else
        m = mod((q.y - p.y) * inv(q.x - p.x, P), P);
    cpp_int rx = mod(m * m - p.x - q.x, P);
    cpp_int ry = mod(m * (p.x - rx) - p.y, P);
    return {rx, ry, false};
}

static Point mul_pt(Point p, cpp_int k) {
    Point r{0, 0, true};
    while (k > 0) {
        if (k & 1) r = add_pt(r, p);
        p = add_pt(p, p);
        k >>= 1;
    }
    return r;
}

static std::pair<cpp_int, cpp_int> ecdsa_sign_16(const cpp_int& priv, const cpp_int& z) {
    cpp_int k = generateRandom16(N_ecc);
    Point R = mul_pt({Gx, Gy, false}, k);
    cpp_int r = mod(R.x, N_ecc);
    cpp_int s = mod(inv(k, N_ecc) * (z + r * priv), N_ecc);
    return {r, s};
}

static bool ecdsa_verify_16(const Point& pub, const cpp_int& z, cpp_int r, cpp_int s) {
    cpp_int w = inv(s, N_ecc);
    cpp_int u1 = mod(z * w, N_ecc), u2 = mod(r * w, N_ecc);
    Point X = add_pt(mul_pt({Gx, Gy, false}, u1), mul_pt(pub, u2));
    return mod(X.x, N_ecc) == r;
}

void run_ecc_encrypt() {
    Point G{Gx, Gy, false};
    std::string msg, priv_recv_str, priv_send_str;
    std::cout << "Plaintext: ";
    std::getline(std::cin, msg);

    std::cout << "Enter Custom Receiver Private Key (HEX) [Enter to auto-generate]: ";
    std::getline(std::cin, priv_recv_str);
    std::cout << "Enter Custom Sender Private Key (HEX) [Enter to auto-generate]: ";
    std::getline(std::cin, priv_send_str);

    auto total_start = std::chrono::steady_clock::now();

    // Step 1: Key Generation
    auto s1_start = std::chrono::steady_clock::now();
    cpp_int priv_recv = priv_recv_str.empty() ? generateRandom16(N_ecc) : cpp_int("0x" + priv_recv_str);
    Point pub_recv = mul_pt(G, priv_recv);

    cpp_int priv_send = priv_send_str.empty() ? generateRandom16(N_ecc) : cpp_int("0x" + priv_send_str);
    Point pub_send = mul_pt(G, priv_send);
    auto s1_end = std::chrono::steady_clock::now();

    // Step 2: ECDH Ephemeral Key Exchange & AES Encryption
    auto s2_start = std::chrono::steady_clock::now();
    cpp_int k_eph = generateRandom16(N_ecc);
    Point R_eph = mul_pt(G, k_eph);
    Point S = mul_pt(pub_recv, k_eph);

    std::vector<Byte> sx = {static_cast<Byte>((S.x >> 8) & 0xFF), static_cast<Byte>(S.x & 0xFF)};
    auto h = CryptoSHA32::compute(sx);
    uint16_t aesKey = (h[0] << 8) | h[1];

    uint16_t block = msg.empty() ? 0x0000 : static_cast<uint16_t>(msg[0]);
    uint16_t ct_block = CryptoAES16::encrypt(block, aesKey);
    auto s2_end = std::chrono::steady_clock::now();

    // Step 3: ECDSA Signature Generation
    auto s3_start = std::chrono::steady_clock::now();
    std::vector<Byte> ct_bytes = {static_cast<Byte>(ct_block >> 8), static_cast<Byte>(ct_block & 0xFF)};
    auto hct = CryptoSHA32::compute(ct_bytes);
    cpp_int z = CryptoSHA32::to_uint32(hct);

    auto sig = ecdsa_sign_16(priv_send, z);
    auto s3_end = std::chrono::steady_clock::now();

    auto total_end = std::chrono::steady_clock::now();

    std::chrono::duration<double, std::milli> s1_ms = s1_end - s1_start;
    std::chrono::duration<double, std::milli> s2_ms = s2_end - s2_start;
    std::chrono::duration<double, std::milli> s3_ms = s3_end - s3_start;
    std::chrono::duration<double, std::milli> total_ms = total_end - total_start;

    std::cout << "\n================ [ECC-16 / SHA-32 / AES-16 Output] ================\n";
    std::cout << "[Receiver Private Key]\n0x" << std::hex << priv_recv << "\n\n";
    std::cout << "[Ephemeral Public Key R_eph X, Y]\n0x" << R_eph.x << "\n0x" << R_eph.y << "\n\n";
    std::cout << "[Sender Public Key X, Y]\n0x" << pub_send.x << "\n0x" << pub_send.y << "\n\n";
    std::cout << "[AES-16 Ciphertext Block HEX]\n0x" << std::setw(4) << std::setfill('0') << ct_block << "\n\n";
    std::cout << "[ECDSA Signature r, s]\n0x" << sig.first << "\n0x" << sig.second << "\n";
    std::cout << "-------------------------------------------------------------------\n";
    std::cout << "[Performance Metrics]\n";
    std::cout << "Step 1 (Key Generation)  : " << s1_ms.count() << " ms\n";
    std::cout << "Step 2 (ECDH & AES Enc)  : " << s2_ms.count() << " ms\n";
    std::cout << "Step 3 (ECDSA Sign)      : " << s3_ms.count() << " ms\n";
    std::cout << "Total Encryption Time    : " << total_ms.count() << " ms\n";
    std::cout << "===================================================================\n" << std::dec;
}

void run_ecc_decrypt() {
    Point G{Gx, Gy, false};
    std::string priv_recv_str, re_x_str, re_y_str, ps_x_str, ps_y_str, ct_hex, r_str, s_str;

    std::cout << "Receiver Private Key (HEX): "; std::cin >> priv_recv_str;
    std::cout << "Ephemeral Public Key R_eph X Y (HEX):\n"; std::cin >> re_x_str >> re_y_str;
    std::cout << "Sender Public Key X Y (HEX):\n"; std::cin >> ps_x_str >> ps_y_str;
    std::cout << "Ciphertext Block (HEX): "; std::cin >> ct_hex;
    std::cout << "Signature r s (HEX):\n"; std::cin >> r_str >> s_str;

    auto total_start = std::chrono::steady_clock::now();

    cpp_int priv_recv("0x" + priv_recv_str);
    Point R_eph{cpp_int("0x" + re_x_str), cpp_int("0x" + re_y_str), false};
    Point pub_send{cpp_int("0x" + ps_x_str), cpp_int("0x" + ps_y_str), false};
    cpp_int r("0x" + r_str), s("0x" + s_str);
    uint16_t ct_block = static_cast<uint16_t>(std::stoul(ct_hex, nullptr, 16));

    // Step 1: ECDSA Signature Verification
    auto s1_start = std::chrono::steady_clock::now();
    std::vector<Byte> ct_bytes = {static_cast<Byte>(ct_block >> 8), static_cast<Byte>(ct_block & 0xFF)};
    auto hct = CryptoSHA32::compute(ct_bytes);
    cpp_int z = CryptoSHA32::to_uint32(hct);

    bool ok = ecdsa_verify_16(pub_send, z, r, s);
    auto s1_end = std::chrono::steady_clock::now();

    // Step 2: ECDH Shared Secret & AES Decryption
    auto s2_start = std::chrono::steady_clock::now();
    Point S = mul_pt(R_eph, priv_recv);
    std::vector<Byte> sx = {static_cast<Byte>((S.x >> 8) & 0xFF), static_cast<Byte>(S.x & 0xFF)};
    auto h = CryptoSHA32::compute(sx);
    uint16_t aesKey = (h[0] << 8) | h[1];

    uint16_t pt_block = CryptoAES16::decrypt(ct_block, aesKey);
    auto s2_end = std::chrono::steady_clock::now();

    auto total_end = std::chrono::steady_clock::now();

    std::chrono::duration<double, std::milli> s1_ms = s1_end - s1_start;
    std::chrono::duration<double, std::milli> s2_ms = s2_end - s2_start;
    std::chrono::duration<double, std::milli> total_ms = total_end - total_start;

    std::cout << "\n================ [Decryption and Verify Result] ================\n";
    if (ok) {
        std::cout << "[+] ECDSA Signature Status : VALID (Signature Verification Success)\n";
        std::cout << "[+] Decrypted Plaintext     : " << static_cast<char>(pt_block & 0xFF) << "\n";
    } else {
        std::cout << "[-] ECDSA Signature Status : INVALID (Signature Verification Failed!)\n";
    }
    std::cout << "-----------------------------------------------------------------\n";
    std::cout << "[Performance Metrics]\n";
    std::cout << "Step 1 (ECDSA Verify)    : " << s1_ms.count() << " ms\n";
    std::cout << "Step 2 (ECDH & AES Dec)  : " << s2_ms.count() << " ms\n";
    std::cout << "Total Decryption Time    : " << total_ms.count() << " ms\n";
    std::cout << "=================================================================\n" << std::dec;
}