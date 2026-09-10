#include <random>
#include <boost/multiprecision/cpp_int.hpp>
#include "ECCVER.hpp"
#include "CryptoUtils.hpp"

using boost::multiprecision::cpp_int;
using Byte = uint8_t;
using Block = std::array<Byte,16>;

/* ================= secp256k1 도메인 파라미터 ================= */
const cpp_int P("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
const cpp_int N("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
const cpp_int Gx("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
const cpp_int Gy("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
struct Point{ cpp_int x,y; bool inf=false; };

/* ================= MOD & 난수 ================= */

cpp_int generateRandom256(const cpp_int& max_val) {
    std::random_device rd;
    std::mt19937_64 eng(rd());
    std::uniform_int_distribution<uint64_t> dist(0, 0xFFFFFFFFFFFFFFFFULL);

    cpp_int random_val = 0;
    for (int i = 0; i < 4; ++i) {
        random_val = (random_val << 64) | dist(eng);
    }
    return mod(random_val, max_val - 1) + 1;
}

/* ================= ECC 연산 ================= */
Point add(Point p, Point q){
    if(p.inf) return q;
    if(q.inf) return p;
    if(p.x==q.x && mod(p.y+q.y,P)==0) return {0,0,true};
    cpp_int m;
    if(p.x==q.x && p.y==q.y)
        m = mod((3*p.x*p.x)*inv(2*p.y,P),P);
    else
        m = mod((q.y-p.y)*inv(q.x-p.x,P),P);
    cpp_int rx = mod(m*m-p.x-q.x,P);
    cpp_int ry = mod(m*(p.x-rx)-p.y,P);
    return {rx,ry,false};
}

Point mul(Point p, cpp_int k){
    Point r{0,0,true};
    while(k>0){
        if(k&1) r=add(r,p);
        p=add(p,p);
        k>>=1;
    }
    return r;
}

/* ================= ECDSA ================= */
std::pair<cpp_int,cpp_int> sign(const cpp_int& priv, const cpp_int& z){
    cpp_int k = generateRandom256(N);
    Point R = mul({Gx,Gy,false}, k);
    cpp_int r = mod(R.x, N);
    cpp_int s = mod(inv(k, N) * (z + r * priv), N);
    return {r, s};
}

bool verify(const Point& pub, const cpp_int& z, cpp_int r, cpp_int s){
    cpp_int w = inv(s, N);
    cpp_int u1 = mod(z * w, N), u2 = mod(r * w, N);
    Point X = add(mul({Gx,Gy,false}, u1), mul(pub, u2));
    return mod(X.x, N) == r;
}

/* ================= MAIN ================= */
void run_ecc_encrypt() {
    Point G{Gx,Gy,false};
    std::string msg;
    std::cout<<"Plaintext: ";
    std::getline(std::cin, msg);

    // 1. 수신자(Receiver)의 키쌍 생성 (데모용)
    cpp_int priv_recv = generateRandom256(N);
    Point pub_recv = mul(G, priv_recv);

    // 2. 송신자(Sender)의 키쌍 생성
    cpp_int priv_send = generateRandom256(N);
    Point pub_send = mul(G, priv_send);

    // 3. [공개키 암호화] 임시(Ephemeral) 키 생성 및 수신자 공개키로 공유 비밀(S) 계산
    cpp_int k_eph = generateRandom256(N);
    Point R_eph = mul(G, k_eph);             // 암호문과 함께 보낼 임시 공개키
    Point S = mul(pub_recv, k_eph);          // S = k_eph * Pub_recv (수신자 공개키로 암호화)

    // 4. KDF: SHA-256(S.x) → AES-128 Key 생성
    std::vector<Byte> sx;
    cpp_int tx = S.x;
    for(int i=0; i<32; i++){ sx.insert(sx.begin(), (Byte)(tx&0xff)); tx>>=8; }
    auto h = sha256(sx);
    Block aesKey{};
    for(int i=0; i<16; i++) aesKey[i] = h[i];

    // 5. 메시지 암호화
    auto ct = aesCTR({msg.begin(), msg.end()}, aesKey);

    // 6. [전자서명] 송신자의 개인키로 암호문 해시 서명
    auto hct = sha256(ct);
    cpp_int z = 0; for(auto b:hct) z = (z<<8) | b;
    auto sig = sign(priv_send, z);

    std::cout << "\n================ [출력 데이터] ================\n";
    std::cout << "[Receiver Private Key (복호화 시 사용)]\n" << priv_recv << "\n\n";
    std::cout << "[Ephemeral Public Key R_eph X, Y (복호화 시 필요)]\n" << R_eph.x << "\n" << R_eph.y << "\n\n";
    std::cout << "[Sender Public Key X, Y (서명 검증 시 필요)]\n" << pub_send.x << "\n" << pub_send.y << "\n\n";
    std::cout << "[Ciphertext HEX]\n";
    for(auto b:ct) std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)b;
    std::cout<<std::dec<<"\n\n[Signature r, s]\n"<<sig.first<<"\n"<<sig.second<<"\n";
    std::cout << "=================================================\n";
}

void run_ecc_decrypt() {
    Point G{Gx,Gy,false};
    cpp_int priv_recv, re_x, re_y, ps_x, ps_y, r, s;
    std::string hex;

    std::cout<<"Receiver Private Key: "; std::cin>>priv_recv;
    std::cout<<"Ephemeral Public Key R_eph X Y:\n"; std::cin>>re_x>>re_y;
    std::cout<<"Sender Public Key X Y:\n"; std::cin>>ps_x>>ps_y;
    std::cin.ignore();
    std::cout<<"Ciphertext HEX: "; std::getline(std::cin, hex);
    std::cout<<"Signature r s:\n"; std::cin>>r>>s;

    std::vector<Byte> ct;
    for(size_t i=0; i<hex.size(); i+=2)
        ct.push_back(std::stoi(hex.substr(i,2), nullptr, 16));

    // 1. 송신자 서명 검증 (Sender Public Key 사용)
    auto hct = sha256(ct);
    cpp_int z = 0; for(auto b:hct) z = (z<<8) | b;
    bool ok = verify({ps_x, ps_y, false}, z, r, s);

    // 2. [공개키 복호화] 수신자 개인키와 임시 공개키 R_eph 곱하여 공유 비밀(S) 복원
    Point R_eph{re_x, re_y, false};
    Point S = mul(R_eph, priv_recv);        // S = priv_recv * R_eph

    // 3. KDF: SHA-256(S.x) → AES Key 복원
    std::vector<Byte> sx;
    cpp_int tx = S.x;
    for(int i=0; i<32; i++){ sx.insert(sx.begin(), (Byte)(tx&0xff)); tx>>=8; }
    auto h = sha256(sx);
    Block aesKey{}; for(int i=0; i<16; i++) aesKey[i] = h[i];

    // 4. 복호화 실행
    auto pt = aesCTR(ct, aesKey);

    std::cout << "\n================ [검증 및 복호화 결과] ================\n";
    if (ok) {
        std::cout << "[+] Signature Status : VALID (송신자 서명 검증 성공)\n";
        std::cout << "[+] Decrypted Plaintext : " << std::string(pt.begin(), pt.end()) << "\n";
    }
    else {
        std::cout << "[-] Signature Status : INVALID (서명 검증 실패! 변조된 메시지입니다)\n";
    }
    std::cout << "========================================================\n";
}



