#include <iostream>
#include "ECCVER.hpp"
#include "RSAVER.hpp"

int main() {
    std::cout << "======================================\n";
    std::cout << "   Advanced Hybrid Cryptography Tool  \n";
    std::cout << "======================================\n";

    while (true) {
        std::cout << "\n[ Algorithm Selection ]\n";
        std::cout << "1. ECC (ECDH Key Exchange + ECDSA Signature)\n";
        std::cout << "2. RSA (RSA-KEM + RSA-PSS Signature)\n";
        std::cout << "0. Exit\n";
        std::cout << "Select > ";

        int algo;
        if (!(std::cin >> algo) || algo == 0) break;

        std::cout << "\n[ Operation Selection ]\n";
        std::cout << "1. Encrypt and Sign (Tx)\n";
        std::cout << "2. Decrypt and Verify (Rx)\n";
        std::cout << "Select > ";

        int op;
        std::cin >> op;
        std::cin.ignore(); // 버퍼 비우기

        if (algo == 1) {
            if (op == 1) run_ecc_encrypt();
            else if (op == 2) run_ecc_decrypt();
            else std::cout << "Invalid operation.\n";
        }
        else if (algo == 2) {
            if (op == 1) run_rsa_encrypt();
            else if (op == 2) run_rsa_decrypt();
            else std::cout << "Invalid operation.\n";
        }
        else {
            std::cout << "Invalid algorithm.\n";
        }
    }

    std::cout << "Exiting program. Goodbye!\n";
    return 0;
}