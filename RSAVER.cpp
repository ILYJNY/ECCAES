#include <random>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/miller_rabin.hpp> // 소수 판별용
#include "CryptoUtils.hpp"
using boost::multiprecision::cpp_int;
using Byte = uint8_t;
using Block = std::array<Byte, 16>;

/* ================= RSA 키 생성 ================= */
// Miller-Rabin 테스트를 거친 임의의 소수 생성
cpp_int generate_prime(int bits) {
    std::random_device rd;
    std::mt19937_64 eng(rd());
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);
    
    cpp_int p;
    do {
        p = 0;
        for (int i = 0; i < bits / 32; ++i) {
            p = (p << 32) | dist(eng);
        }
        boost::multiprecision::bit_set(p, bits - 1); // 최상위 비트를 1로 (길이 보장)
        boost::multiprecision::bit_set(p, 0);        // 최하위 비트를 1로 (홀수 보장)
    } while (!boost::multiprecision::miller_rabin_test(p, 25)); // 25번 검증으로 99.999...% 소수 확정
    return p;
}

struct RSAKey {
    cpp_int n, e, d;
};

// 1024비트 RSA 키쌍 생성 (p, q는 각각 512비트)
RSAKey generate_rsa_key() {
    cpp_int p = generate_prime(512);
    cpp_int q = generate_prime(512);
    cpp_int n = p * q;
    cpp_int phi = (p - 1) * (q - 1);
    cpp_int e = 65537; // 가장 널리 쓰이는 표준 지수
    cpp_int d = inv(e, phi);
    return {n, e, d};
}

/* ================= 바이트 배열 <-> 정수 변환 ================= */
cpp_int bytes_to_int(const std::vector<Byte>& v) {
    cpp_int res = 0;
    for (auto b : v) res = (res << 8) | b;
    return res;
}

std::vector<Byte> int_to_bytes(cpp_int val, size_t length) {
    std::vector<Byte> res(length, 0);
    for (int i = length - 1; i >= 0; i--) {
        res[i] = static_cast<Byte>(val & 0xFF);
        val >>= 8;
    }
    return res;
}


/* ================= RSA-PSS 도구 (RFC 8017) ================= */
// MGF1 (Mask Generation Function 1)
std::vector<Byte> mgf1(const std::vector<Byte>& seed, size_t maskLen) {
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
        auto h = sha256(toHash);
        T.insert(T.end(), h.begin(), h.end());
        counter++;
    }
    T.resize(maskLen);
    return T;
}

// PSS Encode
std::vector<Byte> pss_encode(const std::vector<Byte>& mHash, size_t emBits) {
    size_t emLen = (emBits + 7) / 8; // 1024비트 N의 경우 128바이트
    size_t hLen = 32, sLen = 32;

    // 1. 임의의 Salt 생성
    std::vector<Byte> salt(sLen);
    std::random_device rd; std::mt19937 eng(rd()); 
    std::uniform_int_distribution<int> d(0, 255);
    for (int i = 0; i < sLen; i++) salt[i] = d(eng);
    
    // 2. M' = (0x00 * 8) || mHash || salt 생성 및 해싱 -> H
    std::vector<Byte> M_prime(8, 0x00);
    M_prime.insert(M_prime.end(), mHash.begin(), mHash.end());
    M_prime.insert(M_prime.end(), salt.begin(), salt.end());
    auto H_arr = sha256(M_prime);
    std::vector<Byte> H(H_arr.begin(), H_arr.end());
    
    // 3. DB = PS || 0x01 || salt 생성
    std::vector<Byte> DB(emLen - sLen - hLen - 2, 0x00); // PS 영역
    DB.push_back(0x01);
    DB.insert(DB.end(), salt.begin(), salt.end());
    
    // 4. dbMask = MGF1(H) 적용하여 maskedDB 생성
    std::vector<Byte> dbMask = mgf1(H, emLen - hLen - 1);
    std::vector<Byte> maskedDB(DB.size());
    for (size_t i = 0; i < DB.size(); i++) maskedDB[i] = DB[i] ^ dbMask[i];
    
    // 5. 최상위 비트(Zero) 마스킹 처리 (N보다 작게 만들기 위함)
    Byte mask = (0xFF >> (8 * emLen - emBits));
    maskedDB[0] &= mask;
    
    // 6. EM = maskedDB || H || 0xbc 조합
    std::vector<Byte> EM = maskedDB;
    EM.insert(EM.end(), H.begin(), H.end());
    EM.push_back(0xBC);
    
    return EM;
}

// PSS Verify
bool pss_verify(const std::vector<Byte>& mHash, const std::vector<Byte>& EM, size_t emBits) {
    size_t emLen = (emBits + 7) / 8;
    if (EM.size() != emLen) return false;
    size_t hLen = 32, sLen = 32;
    
    if (EM.back() != 0xBC) return false; // 구조 검증
    
    std::vector<Byte> maskedDB(EM.begin(), EM.begin() + emLen - hLen - 1);
    std::vector<Byte> H(EM.begin() + emLen - hLen - 1, EM.end() - 1);
    
    // 최상위 비트 검증
    Byte mask = (0xFF >> (8 * emLen - emBits));
    if ((maskedDB[0] & ~mask) != 0) return false;
    
    // DB 마스크 복원
    std::vector<Byte> dbMask = mgf1(H, emLen - hLen - 1);
    std::vector<Byte> DB(maskedDB.size());
    for (size_t i = 0; i < DB.size(); i++) DB[i] = maskedDB[i] ^ dbMask[i];
    DB[0] &= mask;
    
    // DB 내부의 PS, 0x01 마커 확인
    size_t psLen = emLen - sLen - hLen - 2;
    for (size_t i = 0; i < psLen; i++) {
        if (DB[i] != 0x00) return false;
    }
    if (DB[psLen] != 0x01) return false;
    
    // Salt 추출 후 H 재계산 및 비교
    std::vector<Byte> salt(DB.begin() + psLen + 1, DB.end());
    std::vector<Byte> M_prime(8, 0x00);
    M_prime.insert(M_prime.end(), mHash.begin(), mHash.end());
    M_prime.insert(M_prime.end(), salt.begin(), salt.end());
    
    auto H_calc_arr = sha256(M_prime);
    for (size_t i = 0; i < hLen; i++) {
        if (H[i] != H_calc_arr[i]) return false;
    }
    return true;
}



/* ================= MAIN (하이브리드 암호 시스템) ================= */

void run_rsa_encrypt() {
    // 기존 main() 안에 있던 c == 1 일 때의 암호화 및 서명 로직
    std::string msg;
    std::cout << "Plaintext: ";
    std::getline(std::cin, msg);

    std::cout << "\n[!] Generating 1024-bit RSA Keys (Please wait a moment...)\n";
    RSAKey recv_key = generate_rsa_key(); // 수신자 키쌍
    RSAKey send_key = generate_rsa_key(); // 송신자 키쌍

    // 1. [RSA-KEM] 임의의 256비트 시드(R_seed) 생성 및 수신자 공개키로 암호화
    cpp_int R_seed = generate_prime(256); // 난수로 대체 사용
    cpp_int C_key = modpow(R_seed, recv_key.e, recv_key.n); // C = R_seed^e mod n

    // 2. [KDF] 시드를 해싱하여 16바이트 AES Key 유도
    auto seed_bytes = int_to_bytes(R_seed, 32);
    auto h_seed = sha256(seed_bytes);
    Block aesKey{};
    for (int i = 0; i < 16; i++) aesKey[i] = h_seed[i];

    // 3. 메시지 AES-CTR 암호화
    auto ct = aesCTR({msg.begin(), msg.end()}, aesKey);

    // 4. [RSA-PSS 서명] 암호문 해시 후 MGF1 구조로 인코딩 및 서명
    auto hct_arr = sha256(ct);
    std::vector<Byte> mHash(hct_arr.begin(), hct_arr.end());

    size_t emBits = 1024 - 1; // 1024비트 N을 기준으로 함
    std::vector<Byte> EM = pss_encode(mHash, emBits);
    cpp_int em_int = bytes_to_int(EM);
    cpp_int signature = modpow(em_int, send_key.d, send_key.n); // S = EM^d mod n

    // 결과 출력 (가독성을 위해 16진수로 출력)
    std::cout << "\n================ [출력 데이터] ================\n";
    std::cout << "[Receiver Private Key (d)]\n" << std::hex << recv_key.d << "\n\n";
    std::cout << "[Receiver Public Key (n)]\n" << recv_key.n << "\n\n";
    std::cout << "[Sender Public Key (n)]\n" << send_key.n << "\n\n";
    std::cout << "[Encrypted AES Seed (C_key)]\n" << C_key << "\n\n";

    std::cout << "[Ciphertext HEX]\n";
    for (auto b : ct) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    std::cout << "\n\n";

    std::cout << "[RSA-PSS Signature]\n" << signature << "\n";
    std::cout << "=================================================\n" << std::dec;
}

void run_rsa_decrypt() {
    // 기존 main() 안에 있던 c == 2 일 때의 복호화 및 검증 로직
    std::string priv_recv_str, pub_recv_n_str, pub_send_n_str, c_key_str, ct_hex, sig_str;

        // 16진수 문자열로 입력받기
        std::cout << "Receiver Private Key (d, HEX): "; std::cin >> std::hex >> priv_recv_str;
        std::cout << "Receiver Public Key (n, HEX): "; std::cin >> pub_recv_n_str;
        std::cout << "Sender Public Key (n, HEX): "; std::cin >> pub_send_n_str;
        std::cout << "Encrypted AES Seed (C_key, HEX): "; std::cin >> c_key_str;
        std::cin.ignore();
        std::cout << "Ciphertext HEX: "; std::getline(std::cin, ct_hex);
        std::cout << "RSA-PSS Signature (HEX): "; std::cin >> sig_str;

        cpp_int priv_recv("0x" + priv_recv_str);
        cpp_int recv_n("0x" + pub_recv_n_str);
        cpp_int send_n("0x" + pub_send_n_str);
        cpp_int C_key("0x" + c_key_str);
        cpp_int signature("0x" + sig_str);

        std::vector<Byte> ct;
        for (size_t i = 0; i < ct_hex.size(); i += 2)
            ct.push_back(std::stoi(ct_hex.substr(i, 2), nullptr, 16));

        // 1. [RSA-PSS 서명 검증]
        cpp_int em_recovered_int = modpow(signature, 65537, send_n); // EM = S^e mod n
        std::vector<Byte> EM = int_to_bytes(em_recovered_int, 128);  // 1024비트 = 128바이트

        auto hct_arr = sha256(ct);
        std::vector<Byte> mHash(hct_arr.begin(), hct_arr.end());
        bool ok = pss_verify(mHash, EM, 1024 - 1);

        // 2. [RSA 복호화] 수신자 개인키로 난수(Seed) 복원
        cpp_int R_seed = modpow(C_key, priv_recv, recv_n);

        // 3. [KDF] 복원된 시드로 AES Key 유도
        auto seed_bytes = int_to_bytes(R_seed, 32);
        auto h_seed = sha256(seed_bytes);
        Block aesKey{};
        for (int i = 0; i < 16; i++) aesKey[i] = h_seed[i];

        // 4. 복호화 실행
        auto pt = aesCTR(ct, aesKey);

        std::cout << "\n================ [검증 및 복호화 결과] ================\n";
        if (ok) {
            std::cout << "[+] PSS Signature Status : VALID (송신자 서명 검증 성공)\n";
            std::cout << "[+] Decrypted Plaintext  : " << std::string(pt.begin(), pt.end()) << "\n";
        } else {
            std::cout << "[-] PSS Signature Status : INVALID (서명 검증 실패!)\n";
        }
        std::cout << "========================================================\n" << std::dec;
}
