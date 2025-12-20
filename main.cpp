#include <iostream>
#include <vector>
#include <array>
#include <string>
#include <iomanip>
#include <sstream>
#include <boost/multiprecision/cpp_int.hpp>

using boost::multiprecision::cpp_int;
using Byte = uint8_t;
using Block = std::array<Byte,16>;

/* ================= secp256k1 ================= */
const cpp_int P("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
const cpp_int N("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
const cpp_int Gx("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
const cpp_int Gy("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
struct Point{ cpp_int x,y; bool inf=false; };

/* ================= MOD ================= */
cpp_int mod(cpp_int a, cpp_int m){ return (a%m+m)%m; }
cpp_int inv(cpp_int a, cpp_int m){
    cpp_int t=0,newt=1,r=m,newr=mod(a,m);
    while(newr!=0){
        cpp_int q=r/newr;
        std::tie(t,newt)=std::make_pair(newt,t-q*newt);
        std::tie(r,newr)=std::make_pair(newr,r-q*newr);
    }
    return mod(t,m);
}

/* ================= ECC ================= */
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

/* ================= SHA-256 ================= */
uint32_t rotr(uint32_t x,uint32_t n){return (x>>n)|(x<<(32-n));}
std::array<Byte,32> sha256(const std::vector<Byte>& data){
    static const uint32_t K[64]={
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
    uint64_t bitlen=data.size()*8;
    std::vector<Byte> msg=data;
    msg.push_back(0x80);
    while((msg.size()*8)%512!=448) msg.push_back(0);
    for(int i=7;i>=0;i--) msg.push_back((bitlen>>(8*i))&0xff);

    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    for(size_t c=0;c<msg.size();c+=64){
        uint32_t w[64];
        for(int i=0;i<16;i++)
            w[i]=(msg[c+4*i]<<24)|(msg[c+4*i+1]<<16)|(msg[c+4*i+2]<<8)|msg[c+4*i+3];
        for(int i=16;i<64;i++){
            uint32_t s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
            uint32_t s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
            w[i]=w[i-16]+s0+w[i-7]+s1;
        }
        uint32_t a=h[0],b=h[1],c_=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for(int i=0;i<64;i++){
            uint32_t S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
            uint32_t ch=(e&f)^((~e)&g);
            uint32_t temp1=hh+S1+ch+K[i]+w[i];
            uint32_t S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
            uint32_t maj=(a&b)^(a&c_)^(b&c_);
            uint32_t temp2=S0+maj;
            hh=g; g=f; f=e; e=d+temp1;
            d=c_; c_=b; b=a; a=temp1+temp2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c_;h[3]+=d;
        h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    std::array<Byte,32> out{};
    for(int i=0;i<8;i++){
        out[4*i]=(h[i]>>24)&0xff;
        out[4*i+1]=(h[i]>>16)&0xff;
        out[4*i+2]=(h[i]>>8)&0xff;
        out[4*i+3]=h[i]&0xff;
    }
    return out;
}

/* ================= AES-128 ================= */
static const Byte SBOX[256]={
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  /* … (중략 없음: 실제로는 256개 전부 필요) … */
};
/* 위 SBOX는 길이상 생략했지만,
   실제 사용 시 256바이트 전체를 이전 메시지의 SBOX 그대로 붙여 넣어라. */

Byte xtime(Byte x){ return (x<<1) ^ ((x&0x80)?0x1b:0); }
void subBytes(Block& s){ for(auto& b:s) b=SBOX[b]; }
void shiftRows(Block& s){
    Block t=s;
    s[1]=t[5]; s[5]=t[9]; s[9]=t[13]; s[13]=t[1];
    s[2]=t[10]; s[6]=t[14]; s[10]=t[2]; s[14]=t[6];
    s[3]=t[15]; s[7]=t[3]; s[11]=t[7]; s[15]=t[11];
}
void mixColumns(Block& s){
    for(int i=0;i<4;i++){
        Byte a=s[4*i],b=s[4*i+1],c=s[4*i+2],d=s[4*i+3];
        s[4*i]  = xtime(a)^xtime(b)^b^c^d;
        s[4*i+1]= a^xtime(b)^xtime(c)^c^d;
        s[4*i+2]= a^b^xtime(c)^xtime(d)^d;
        s[4*i+3]= xtime(a)^a^b^c^xtime(d);
    }
}
void addRoundKey(Block& s,const Block& k){ for(int i=0;i<16;i++) s[i]^=k[i]; }

std::array<Block,11> keySchedule(const Block& key){
    static const Byte RCON[10]={1,2,4,8,16,32,64,128,27,54};
    std::array<Block,11> rk{};
    rk[0]=key;
    for(int r=1;r<=10;r++){
        rk[r]=rk[r-1];
        Byte t[4]={rk[r][13],rk[r][14],rk[r][15],rk[r][12]};
        for(int i=0;i<4;i++) t[i]=SBOX[t[i]];
        t[0]^=RCON[r-1];
        for(int i=0;i<4;i++) rk[r][i]^=t[i];
        for(int i=4;i<16;i++) rk[r][i]^=rk[r][i-4];
    }
    return rk;
}
Block aesEncrypt(Block s,const std::array<Block,11>& rk){
    addRoundKey(s,rk[0]);
    for(int r=1;r<10;r++){ subBytes(s); shiftRows(s); mixColumns(s); addRoundKey(s,rk[r]); }
    subBytes(s); shiftRows(s); addRoundKey(s,rk[10]);
    return s;
}

/* ================= AES-CTR ================= */
std::vector<Byte> aesCTR(const std::vector<Byte>& data,const Block& key){
    auto rk=keySchedule(key);
    std::vector<Byte> out=data;
    Block ctr{};
    for(size_t i=0;i<data.size();i++){
        if(i%16==0) ctr=aesEncrypt(ctr,rk);
        out[i]^=ctr[i%16];
    }
    return out;
}

/* ================= ECDSA ================= */
std::pair<cpp_int,cpp_int> sign(const cpp_int& priv,const cpp_int& z){
    cpp_int k=1234567; // 학습용
    Point R=mul({Gx,Gy,false},k);
    cpp_int r=mod(R.x,N);
    cpp_int s=mod(inv(k,N)*(z+r*priv),N);
    return {r,s};
}
bool verify(const Point& pub,const cpp_int& z,cpp_int r,cpp_int s){
    cpp_int w=inv(s,N);
    cpp_int u1=mod(z*w,N), u2=mod(r*w,N);
    Point X=add(mul({Gx,Gy,false},u1),mul(pub,u2));
    return mod(X.x,N)==r;
}

/* ================= MAIN ================= */
int main(){
    std::cout<<"1.Encrypt+Sign\n2.Decrypt+Verify\nSelect: ";
    int c; std::cin>>c; std::cin.ignore();

    Point G{Gx,Gy,false};

    if(c==1){
        std::string msg;
        std::cout<<"Plaintext: ";
        std::getline(std::cin,msg);

        cpp_int priv=11111;
        Point pub=mul(G,priv);

        // ECDH (self-demo)
        Point S=mul(pub,priv);

        // KDF: SHA-256(S.x) → AES-128 key
        std::vector<Byte> sx;
        cpp_int tx=S.x;
        for(int i=0;i<32;i++){ sx.insert(sx.begin(), (Byte)(tx&0xff)); tx>>=8; }
        auto h=sha256(sx);
        Block aesKey{};
        for(int i=0;i<16;i++) aesKey[i]=h[i];

        auto ct=aesCTR({msg.begin(),msg.end()},aesKey);

        // Sign ciphertext hash
        auto hct=sha256(ct);
        cpp_int z=0; for(auto b:hct) z=(z<<8)|b;
        auto sig=sign(priv,z);

        std::cout<<"\n[Public Key]\n"<<pub.x<<"\n"<<pub.y<<"\n";
        std::cout<<"[Ciphertext]\n";
        for(auto b:ct) std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)b;
        std::cout<<"\n[Signature r s]\n"<<sig.first<<"\n"<<sig.second<<"\n";
    }else{
        cpp_int px,py,r,s;
        std::string hex;
        std::cout<<"Public key X Y:\n"; std::cin>>px>>py;
        std::cin.ignore();
        std::cout<<"Ciphertext HEX: "; std::getline(std::cin,hex);
        std::cout<<"Signature r s:\n"; std::cin>>r>>s;

        std::vector<Byte> ct;
        for(size_t i=0;i<hex.size();i+=2)
            ct.push_back(std::stoi(hex.substr(i,2),nullptr,16));

        // ECDH
        cpp_int priv=11111;
        Point S=mul({px,py,false},priv);

        // KDF
        std::vector<Byte> sx;
        cpp_int tx=S.x;
        for(int i=0;i<32;i++){ sx.insert(sx.begin(), (Byte)(tx&0xff)); tx>>=8; }
        auto h=sha256(sx);
        Block aesKey{}; for(int i=0;i<16;i++) aesKey[i]=h[i];

        // Verify
        auto hct=sha256(ct);
        cpp_int z=0; for(auto b:hct) z=(z<<8)|b;
        bool ok=verify({px,py,false},z,r,s);

        auto pt=aesCTR(ct,aesKey);
        if (ok == true) {
            std::cout<<("Signature VALID\n");
            std::cout<<"[Plaintext]\n"<<std::string(pt.begin(),pt.end())<<"\n";
        }
        else {
            std::cout<<("Signature INVALID\n");
        }


    }
}
