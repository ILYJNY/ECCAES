#include <iostream>
#include <vector>
#include <array>
#include <string>
#include <iomanip>
#include <sstream>
#include <random>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/miller_rabin.hpp> // 소수 판별용

using boost::multiprecision::cpp_int;
using Byte = uint8_t;
using Block = std::array<Byte, 16>;

/* ================= 모듈러 연산 및 수학 도구 ================= */
cpp_int mod(cpp_int a, cpp_int m) { return (a % m + m) % m; }

cpp_int modpow(cpp_int base, cpp_int exp, cpp_int mod_val) {
    cpp_int res = 1;
    base = base % mod_val;
    while (exp > 0) {
        if (exp % 2 == 1) res = (res * base) % mod_val;
        base = (base * base) % mod_val;
        exp /= 2;
    }
    return res;
}

cpp_int inv(cpp_int a, cpp_int m) {
    cpp_int t = 0, newt = 1, r = m, newr = mod(a, m);
    while (newr != 0) {
        cpp_int q = r / newr;
        std::tie(t, newt) = std::make_pair(newt, t - q * newt);
        std::tie(r, newr) = std::make_pair(newr, r - q * newr);
    }
    return mod(t, m);
}

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

/* ================= SHA-256 ================= */
uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
std::array<Byte, 32> sha256(const std::vector<Byte>& data) {
    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
        0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
        0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
        0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
        0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
        0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
        0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
        0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
        0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint64_t bitlen = data.size() * 8;
    std::vector<Byte> msg = data;
    msg.push_back(0x80);
    while ((msg.size() * 8) % 512 != 448) msg.push_back(0);
    for (int i = 7; i >= 0; i--) msg.push_back((bitlen >> (8 * i)) & 0xff);

    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    for (size_t c = 0; c < msg.size(); c += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = (msg[c+4*i]<<24)|(msg[c+4*i+1]<<16)|(msg[c+4*i+2]<<8)|msg[c+4*i+3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15]>>3);
            uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2]>>10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0], b=h[1], c_=h[2], d=h[3], e=h[4], f=h[5], g=h[6], hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            uint32_t ch = (e&f) ^ ((~e)&g);
            uint32_t temp1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            uint32_t maj = (a&b) ^ (a&c_) ^ (b&c_);
            uint32_t temp2 = S0 + maj;
            hh=g; g=f; f=e; e=d+temp1;
            d=c_; c_=b; b=a; a=temp1+temp2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c_; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    std::array<Byte,32> out{};
    for(int i=0;i<8;i++){
        out[4*i] = (h[i]>>24)&0xff;
        out[4*i+1] = (h[i]>>16)&0xff;
        out[4*i+2] = (h[i]>>8)&0xff;
        out[4*i+3] = h[i]&0xff;
    }
    return out;
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

/* ================= AES-128 & CTR 모드 (기존 동일) ================= */
static const unsigned char SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

Byte xtime(Byte x) { return (x << 1) ^ ((x & 0x80) ? 0x1b : 0); }
void subBytes(Block& s) { for (auto& b : s) b = SBOX[b]; }
void shiftRows(Block& s) {
    Block t = s;
    s[1] = t[5]; s[5] = t[9]; s[9] = t[13]; s[13] = t[1];
    s[2] = t[10]; s[6] = t[14]; s[10] = t[2]; s[14] = t[6];
    s[3] = t[15]; s[7] = t[3]; s[11] = t[7]; s[15] = t[11];
}
void mixColumns(Block& s) {
    for (int i = 0; i < 4; i++) {
        Byte a = s[4 * i], b = s[4 * i + 1], c = s[4 * i + 2], d = s[4 * i + 3];
        s[4 * i] = xtime(a) ^ xtime(b) ^ b ^ c ^ d;
        s[4 * i + 1] = a ^ xtime(b) ^ xtime(c) ^ c ^ d;
        s[4 * i + 2] = a ^ b ^ xtime(c) ^ xtime(d) ^ d;
        s[4 * i + 3] = xtime(a) ^ a ^ b ^ c ^ xtime(d);
    }
}
void addRoundKey(Block& s, const Block& k) { for (int i = 0; i < 16; i++) s[i] ^= k[i]; }

std::array<Block, 11> keySchedule(const Block& key) {
    static const Byte RCON[10] = {1, 2, 4, 8, 16, 32, 64, 128, 27, 54};
    std::array<Block, 11> rk{};
    rk[0] = key;
    for (int r = 1; r <= 10; r++) {
        rk[r] = rk[r - 1];
        Byte t[4] = {rk[r][13], rk[r][14], rk[r][15], rk[r][12]};
        for (int i = 0; i < 4; i++) t[i] = SBOX[t[i]];
        t[0] ^= RCON[r - 1];
        for (int i = 0; i < 4; i++) rk[r][i] ^= t[i];
        for (int i = 4; i < 16; i++) rk[r][i] ^= rk[r][i - 4];
    }
    return rk;
}

Block aesEncrypt(Block s, const std::array<Block, 11>& rk) {
    addRoundKey(s, rk[0]);
    for (int r = 1; r < 10; r++) { subBytes(s); shiftRows(s); mixColumns(s); addRoundKey(s, rk[r]); }
    subBytes(s); shiftRows(s); addRoundKey(s, rk[10]);
    return s;
}

std::vector<Byte> aesCTR(const std::vector<Byte>& data, const Block& key) {
    auto rk = keySchedule(key);
    std::vector<Byte> out = data;
    Block ctr{};
    Block enc_ctr{};
    for (size_t i = 0; i < data.size(); i++) {
        if (i % 16 == 0) {
            enc_ctr = aesEncrypt(ctr, rk);
            for (int j = 15; j >= 0; --j) { if (++ctr[j] != 0) break; }
        }
        out[i] ^= enc_ctr[i % 16];
    }
    return out;
}

/* ================= MAIN (하이브리드 암호 시스템) ================= */
int main() {
    std::cout << "1. Encrypt + Sign (RSA-KEM & RSA-PSS)\n2. Decrypt + Verify\nSelect: ";
    int c; std::cin >> c; std::cin.ignore();

    if (c == 1) {
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
    else {
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
    return 0;
}