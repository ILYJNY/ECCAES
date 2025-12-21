#include <cstdint>
#include <vector>
#include <array>
#include <cstring>

/* ===================== SHA-256 ===================== */

namespace sha256 {

static constexpr uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t big_sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32_t big_sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32_t small_sigma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint32_t small_sigma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

/* ===== main hash function ===== */
std::array<uint8_t, 32> hash(const std::vector<uint8_t>& data) {
    uint64_t bit_len = static_cast<uint64_t>(data.size()) * 8;

    /* ---- padding ---- */
    std::vector<uint8_t> msg = data;
    msg.push_back(0x80);
    while ((msg.size() % 64) != 56)
        msg.push_back(0x00);

    for (int i = 7; i >= 0; --i)
        msg.push_back((bit_len >> (i * 8)) & 0xFF);

    /* ---- initial hash ---- */
    uint32_t H[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };

    /* ---- process blocks ---- */
    for (size_t offset = 0; offset < msg.size(); offset += 64) {
        uint32_t W[64];

        for (int i = 0; i < 16; ++i) {
            W[i] =
                (msg[offset + 4*i] << 24) |
                (msg[offset + 4*i + 1] << 16) |
                (msg[offset + 4*i + 2] << 8) |
                (msg[offset + 4*i + 3]);
        }

        for (int i = 16; i < 64; ++i) {
            W[i] = small_sigma1(W[i-2]) + W[i-7]
                 + small_sigma0(W[i-15]) + W[i-16];
        }

        uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
        uint32_t e = H[4], f = H[5], g = H[6], h = H[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t T1 = h + big_sigma1(e) + ch(e,f,g) + K[i] + W[i];
            uint32_t T2 = big_sigma0(a) + maj(a,b,c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        H[0] += a; H[1] += b; H[2] += c; H[3] += d;
        H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }

    /* ---- output ---- */
    std::array<uint8_t, 32> out{};
    for (int i = 0; i < 8; ++i) {
        out[i*4]     = (H[i] >> 24) & 0xFF;
        out[i*4 + 1] = (H[i] >> 16) & 0xFF;
        out[i*4 + 2] = (H[i] >> 8) & 0xFF;
        out[i*4 + 3] = H[i] & 0xFF;
    }
    return out;
}

} // namespace sha256
#include <stdexcept>

/* ===================== AES-128 ===================== */
namespace aes128 {

/* ---- S-Box ---- */
static const uint8_t sbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* ---- GF(2^8) multiply ---- */
inline uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00);
}

inline uint8_t mul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return r;
}

/* ---- PKCS7 Padding ---- */
std::vector<uint8_t> pad(const std::vector<uint8_t>& in) {
    size_t padlen = 16 - (in.size() % 16);
    std::vector<uint8_t> out = in;
    out.insert(out.end(), padlen, static_cast<uint8_t>(padlen));
    return out;
}

std::vector<uint8_t> unpad(const std::vector<uint8_t>& in) {
    if (in.empty()) throw std::runtime_error("unpad error");
    uint8_t p = in.back();
    if (p == 0 || p > 16) throw std::runtime_error("bad padding");
    return std::vector<uint8_t>(in.begin(), in.end() - p);
}

/* ---- Key Expansion ---- */
static const uint8_t Rcon[11] = {
0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};

std::array<uint8_t,176> expand_key(const std::array<uint8_t,16>& key) {
    std::array<uint8_t,176> w{};
    for (int i=0;i<16;i++) w[i]=key[i];

    int bytes = 16;
    int r = 1;
    uint8_t t[4];

    while (bytes < 176) {
        for (int i=0;i<4;i++) t[i]=w[bytes-4+i];
        if (bytes % 16 == 0) {
            uint8_t tmp=t[0];
            t[0]=sbox[t[1]] ^ Rcon[r++];
            t[1]=sbox[t[2]];
            t[2]=sbox[t[3]];
            t[3]=sbox[tmp];
        }
        for (int i=0;i<4;i++) {
            w[bytes]=w[bytes-16]^t[i];
            bytes++;
        }
    }
    return w;
}

/* ---- Encrypt single block ---- */
void encrypt_block(uint8_t s[4][4], const std::array<uint8_t,176>& rk) {
    auto ark=[&](int r){
        for(int c=0;c<4;c++)
            for(int i=0;i<4;i++)
                s[i][c]^=rk[r*16+c*4+i];
    };

    ark(0);
    for(int r=1;r<=9;r++){
        for(int i=0;i<4;i++)
            for(int j=0;j<4;j++)
                s[i][j]=sbox[s[i][j]];

        uint8_t t[4];
        for(int i=1;i<4;i++){
            for(int j=0;j<4;j++) t[j]=s[i][(j+i)%4];
            for(int j=0;j<4;j++) s[i][j]=t[j];
        }

        for(int j=0;j<4;j++){
            uint8_t a=s[0][j],b=s[1][j],c=s[2][j],d=s[3][j];
            s[0][j]=mul(a,2)^mul(b,3)^c^d;
            s[1][j]=a^mul(b,2)^mul(c,3)^d;
            s[2][j]=a^b^mul(c,2)^mul(d,3);
            s[3][j]=mul(a,3)^b^c^mul(d,2);
        }
        ark(r);
    }

    for(int i=0;i<4;i++)
        for(int j=0;j<4;j++)
            s[i][j]=sbox[s[i][j]];

    uint8_t t[4];
    for(int i=1;i<4;i++){
        for(int j=0;j<4;j++) t[j]=s[i][(j+i)%4];
        for(int j=0;j<4;j++) s[i][j]=t[j];
    }
    ark(10);
}

/* ---- ECB Encrypt ---- */
std::vector<uint8_t> encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::array<uint8_t,16>& key
) {
    auto data = pad(plaintext);
    auto rk = expand_key(key);

    for(size_t o=0;o<data.size();o+=16){
        uint8_t s[4][4];
        for(int i=0;i<16;i++) s[i%4][i/4]=data[o+i];
        encrypt_block(s,rk);
        for(int i=0;i<16;i++) data[o+i]=s[i%4][i/4];
    }
    return data;
}
    static const uint8_t inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
    };
    void decrypt_block(uint8_t s[4][4], const std::array<uint8_t,176>& rk) {
        auto ark=[&](int r){
            for(int c=0;c<4;c++)
                for(int i=0;i<4;i++)
                    s[i][c]^=rk[r*16+c*4+i];
        };

        ark(10);

        for(int r=9;r>=1;r--){
            uint8_t t[4];
            for(int i=1;i<4;i++){
                for(int j=0;j<4;j++) t[j]=s[i][(j-i+4)%4];
                for(int j=0;j<4;j++) s[i][j]=t[j];
            }

            for(int i=0;i<4;i++)
                for(int j=0;j<4;j++)
                    s[i][j]=inv_sbox[s[i][j]];

            ark(r);

            for(int j=0;j<4;j++){
                uint8_t a=s[0][j],b=s[1][j],c=s[2][j],d=s[3][j];
                s[0][j]=mul(a,14)^mul(b,11)^mul(c,13)^mul(d,9);
                s[1][j]=mul(a,9)^mul(b,14)^mul(c,11)^mul(d,13);
                s[2][j]=mul(a,13)^mul(b,9)^mul(c,14)^mul(d,11);
                s[3][j]=mul(a,11)^mul(b,13)^mul(c,9)^mul(d,14);
            }
        }

        uint8_t t[4];
        for(int i=1;i<4;i++){
            for(int j=0;j<4;j++) t[j]=s[i][(j-i+4)%4];
            for(int j=0;j<4;j++) s[i][j]=t[j];
        }

        for(int i=0;i<4;i++)
            for(int j=0;j<4;j++)
                s[i][j]=inv_sbox[s[i][j]];

        ark(0);
    }
    std::vector<uint8_t> decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::array<uint8_t,16>& key
) {
        auto data = ciphertext;
        auto rk = expand_key(key);

        for(size_t o=0;o<data.size();o+=16){
            uint8_t s[4][4];
            for(int i=0;i<16;i++) s[i%4][i/4]=data[o+i];
            decrypt_block(s,rk);
            for(int i=0;i<16;i++) data[o+i]=s[i%4][i/4];
        }
        return unpad(data);
    }


} // namespace aes128
#include <boost/multiprecision/cpp_int.hpp>


using boost::multiprecision::cpp_int;
namespace ecc {

using Int = cpp_int;

/* ---- secp256k1 parameters ---- */
const Int p =
    (Int(1) << 256) - (Int(1) << 32) - 977;

const Int a = 0;
const Int b = 7;

const Int Gx(
    "55066263022277343669578718895168534326250603453777594175500187360389116729240");
const Int Gy(
    "32670510020758816978083085130507043184471273380659243275938904335757337482424");

const Int n(
    "115792089237316195423570985008687907852837564279074904382605163141518161494337");

/* ---- mod p ---- */
Int mod(const Int& x) {
    Int r = x % p;
    if (r < 0) r += p;
    return r;
}

/* ---- modular inverse ---- */
Int modinv(Int a) {
    Int lm = 1, hm = 0;
    Int low = mod(a), high = p;
    while (low > 1) {
        Int r = high / low;
        Int nm = hm - lm * r;
        Int nw = high - low * r;
        hm = lm; high = low;
        lm = nm; low = nw;
    }
    return mod(lm);
}

/* ---- Point ---- */
struct Point {
    Int x;
    Int y;
    bool inf;

    Point() : x(0), y(0), inf(true) {}
    Point(const Int& x_, const Int& y_) : x(x_), y(y_), inf(false) {}
};

/* ---- Point addition ---- */
Point add(const Point& P, const Point& Q) {
    if (P.inf) return Q;
    if (Q.inf) return P;

    if (P.x == Q.x) {
        if ((P.y + Q.y) % p == 0)
            return Point(); // infinity

        // doubling
        Int s = mod((3 * P.x * P.x + a) * modinv(2 * P.y));
        Int rx = mod(s * s - 2 * P.x);
        Int ry = mod(s * (P.x - rx) - P.y);
        return Point(rx, ry);
    }

    Int s = mod((Q.y - P.y) * modinv(Q.x - P.x));
    Int rx = mod(s * s - P.x - Q.x);
    Int ry = mod(s * (P.x - rx) - P.y);
    return Point(rx, ry);
}

/* ---- Scalar multiplication ---- */
Point mul(Int k, Point P) {
    Point R;
    while (k > 0) {
        if (k & 1) R = add(R, P);
        P = add(P, P);
        k >>= 1;
    }
    return R;
}

/* ---- Key pair ---- */
struct KeyPair {
    Int priv;
    Point pub;
};

/* ---- Generate key pair ---- */
KeyPair generate_key(const Int& priv) {
    Point G(Gx, Gy);
    return { priv % n, mul(priv, G) };
}

/* ===================== ECDH ===================== */

/* ---- Shared secret ---- */
Point ecdh_shared_secret(
    const Int& my_private,
    const Point& other_public
) {
    return mul(my_private, other_public);
}

} // namespace ecc
/* ===================== ECDSA ===================== */

namespace ecdsa {

    using ecc::Int;
    using ecc::Point;
    using ecc::mod;
    using ecc::modinv;
    using ecc::mul;
    using ecc::add;
    using ecc::n;
    using ecc::Gx;
    using ecc::Gy;

    /* ---- Signature ---- */
    struct Signature {
        Int r;
        Int s;
    };

    /* ---- Sign ---- */
    Signature sign(
        const Int& priv,
        const Int& hash,   // z
        const Int& k       // nonce (학습용: 직접 넣음)
    ) {
        Point G(Gx, Gy);
        Point R = mul(k, G);

        Int r = mod(R.x) % n;
        Int s = mod(modinv(k) * (hash + r * priv)) % n;

        return { r, s };
    }

    /* ---- Verify ---- */
    bool verify(
        const Point& pub,
        const Int& hash,
        const Signature& sig
    ) {
        if (sig.r <= 0 || sig.r >= n) return false;
        if (sig.s <= 0 || sig.s >= n) return false;

        Int w = modinv(sig.s);
        Int u1 = mod(hash * w) % n;
        Int u2 = mod(sig.r * w) % n;

        Point G(Gx, Gy);
        Point X = add(mul(u1, G), mul(u2, pub));

        return (X.x % n) == sig.r;
    }

} // namespace ecdsa

#include <iostream>
#include <vector>
#include <array>
#include <string>
#include <sstream>
#include <iomanip>
#include <cassert>
#include <random>
#include <stdexcept>

// ===== 이전 단계 네임스페이스 그대로 사용 =====
// sha256::hash(...)
// aes128::encrypt / decrypt (decrypt 내부에서 padding 제거 가정)
// namespace ecc { ... }
// namespace ecdsa { ... }

// ---------------- PKCS7 Padding (Encrypt 시만 사용) ----------------
std::vector<uint8_t> pad_pkcs7(const std::vector<uint8_t>& data) {
    size_t block_size = 16;
    size_t pad_len = block_size - (data.size() % block_size);
    std::vector<uint8_t> padded = data;
    padded.insert(padded.end(), pad_len, static_cast<uint8_t>(pad_len));
    return padded;
}

// ---------------- Utility ----------------
std::vector<uint8_t> to_bytes(const std::string& s){
    return std::vector<uint8_t>(s.begin(), s.end());
}
std::string to_string(const std::vector<uint8_t>& v){
    return std::string(v.begin(), v.end());
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex){
    std::vector<uint8_t> bytes;
    for(size_t i=0; i<hex.size(); i+=2){
        std::string byteStr = hex.substr(i, 2);
        uint8_t byte = (uint8_t) std::stoul(byteStr, nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}
std::string bytes_to_hex(const std::vector<uint8_t>& v){
    std::ostringstream oss;
    for(auto b: v) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

// ---------------- ECC / ECDH / ECDSA Helper ----------------
std::array<uint8_t,16> kdf_from_ecdh(const ecc::Point& S){
    std::vector<uint8_t> xb;
    boost::multiprecision::export_bits(S.x, std::back_inserter(xb), 8);
    auto h = sha256::hash(xb);
    std::array<uint8_t,16> key{};
    std::copy(h.begin(), h.begin()+16, key.begin());
    return key;
}

ecc::Point input_pubkey(){
    ecc::Int x, y;
    std::cout << "Enter Public Key X: ";
    std::cin >> x;
    std::cout << "Enter Public Key Y: ";
    std::cin >> y;
    return ecc::Point(x, y);
}

ecc::Int input_privkey(){
    ecc::Int priv;
    std::cout << "Enter Private Key: ";
    std::cin >> priv;
    return priv;
}

ecdsa::Signature input_signature(){
    ecc::Int r, s;
    std::cout << "Enter Signature r: ";
    std::cin >> r;
    std::cout << "Enter Signature s: ";
    std::cin >> s;
    return ecdsa::Signature{r, s};
}

ecc::Int generate_random_privkey(){
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(1, 0xFFFFFFFFFFFFFFFF);
    return dis(gen);
}

// ---------------- Main ----------------
int main(){
    std::cout << "Select Function:\n1: Key Generate\n2: Encrypt\n3: Decrypt\nChoice: ";
    int choice;
    std::cin >> choice;
    std::cin.ignore();

    if(choice == 1){
        ecc::Int priv = generate_random_privkey();
        auto key = ecc::generate_key(priv);

        std::cout << "\n[Private Key]\n" << key.priv << "\n";
        std::cout << "[Public Key]\nX: " << key.pub.x << "\nY: " << key.pub.y << "\n";
    }
    else if(choice == 2){
        std::string plaintext;
        std::cout << "Enter Plaintext: ";
        std::getline(std::cin, plaintext);

        std::cout << "Enter Recipient Public Key:\n";
        auto recipient_pub = input_pubkey();

        ecc::Int my_priv = generate_random_privkey();
        auto my_key = ecc::generate_key(my_priv);

        // 1️⃣ 평문 해시로 서명
        auto h_plain = sha256::hash(to_bytes(plaintext));
        ecc::Int z;
        boost::multiprecision::import_bits(z, h_plain.begin(), h_plain.end());
        ecc::Int k_nonce = 11111; // 학습용
        auto sig = ecdsa::sign(my_key.priv, z, k_nonce);

        // 2️⃣ ECDH 공유키 → AES key
        auto S = ecc::ecdh_shared_secret(my_key.priv, recipient_pub);
        auto aes_key = kdf_from_ecdh(S);

        // 3️⃣ AES 암호화 + PKCS7 패딩
        auto pt_bytes = pad_pkcs7(to_bytes(plaintext));
        auto ct = aes128::encrypt(pt_bytes, aes_key);

        std::cout << "\n[Ciphertext HEX]\n" << bytes_to_hex(ct) << "\n";
        std::cout << "\n[Signature]\nr: " << sig.r << "\ns: " << sig.s << "\n";
        std::cout << "\n[Sender Public Key]\nX: " << my_key.pub.x << "\nY: " << my_key.pub.y << "\n";
    }
    else if(choice == 3){
        std::string ct_hex;
        std::cout << "Enter Ciphertext HEX: ";
        std::cin.ignore();
        std::getline(std::cin, ct_hex);
        auto ct = hex_to_bytes(ct_hex);

        std::cout << "Enter Sender Public Key:\n";
        auto sender_pub = input_pubkey();

        auto priv = input_privkey();
        auto sig = input_signature();

        // 1️⃣ ECDH → AES key
        auto S = ecc::ecdh_shared_secret(priv, sender_pub);
        auto aes_key = kdf_from_ecdh(S);
        std::cout << "1 is ok";
        // 2️⃣ AES 복호화 패딩 제거는 AES 내부에서 처리)
        auto pt_bytes = aes128::decrypt(ct, aes_key);
        std::string plaintext = to_string(pt_bytes);
        std::cout << "2 is ok";
        // 3️⃣ 평문 해시 → 서명 검증
        auto h_plain = sha256::hash(pt_bytes);
        ecc::Int z;
        boost::multiprecision::import_bits(z, h_plain.begin(), h_plain.end());

        if(!ecdsa::verify(sender_pub, z, sig)){
            std::cout << "❌ Signature invalid!\n";
            return 0;
        }

        std::cout << "\n✅ Signature valid!\n[Plaintext]\n" << plaintext << "\n";
    }
    else{
        std::cout << "Invalid choice\n";
    }

    return 0;
}
