#include "binfhecontext.h"
#include <string.h>
using namespace lbcrypto;
using std::cout;
using std::endl;
using std::memcpy;

void printBits32(int32_t t) {
    for (int i = 0; i < 32; i++) {
        cout << ((t & (1 << i)) >> i);
    }
    cout << endl;
}

void printBits64(int64_t t) {
    for (int i = 0; i < 64; i++) {
        cout << ((t & (1 << i)) >> i);
    }
    cout << endl;
}

// num1, num2 to compare
// res is an encryption of 0
// return encryption of 0 if num1 equals num2, 1 otherwise
void compare32Bits(LWECiphertext* num1, LWECiphertext* num2, BinFHEContext* cc, LWECiphertext& res) {
    LWECiphertext tmp;
    for (int i = 0; i < 32; i++) {
        tmp = cc -> EvalBinGate(XOR, num1[i], num2[i]);
        res = cc -> EvalBinGate(OR, tmp, res);
    }
    // return res;
}


int main() {
    // Sample Program: Step 1: Set CryptoContext

    auto cc = BinFHEContext();

    // STD128 is the security level of 128 bits of security based on LWE Estimator
    // and HE standard. Other common options are TOY, MEDIUM, STD192, and STD256.
    // MEDIUM corresponds to the level of more than 100 bits for both quantum and
    // classical computer attacks.
    cc.GenerateBinFHEContext(STD128);

    // Sample Program: Step 2: Key Generation

    // Generate the secret key
    auto sk = cc.KeyGen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 3: Encryption

    // Encrypt two ciphertexts representing Boolean True (1).
    // By default, freshly encrypted ciphertexts are bootstrapped.
    // If you wish to get a fresh encryption without bootstrapping, write
    // auto   ct1 = cc.Encrypt(sk, 1, FRESH);
    
    float num1 = 1.25f;
    float num2 = 1.25f;
    int32_t byte1;
    int32_t byte2;
    memcpy(&byte1, &num1, sizeof(float));
    memcpy(&byte2, &num2, sizeof(float));
    

    LWECiphertext ct1 = cc.Encrypt(sk, 1);
    LWECiphertext ct2 = cc.Encrypt(sk, 0);
    

    // LWEPlaintext ptt;
    // cc.Decrypt(sk, ct1, &ptt);
    // cout << "Decryption for 1:" << endl;
    // cc.Decrypt(sk, ct2, &ptt);
    // cout << "Decryption for 0:" << endl;
    // printBits64((int64_t) ptt);

    LWECiphertext ctNum1[32];
    LWECiphertext ctNum2[32];
    LWEPlaintext resultNum1[32];
    LWEPlaintext resultNum2[32];

    cout << "phase 0..." << endl;

    for (int i = 0; i < 32; i++) {
        ctNum1[i] = cc.Encrypt(sk, ((byte1 & (1 << i)) >> i));
        ctNum2[i] = cc.Encrypt(sk, ((byte2 & (1 << i)) >> i));
    }

        
    LWECiphertext res = cc.Encrypt(sk, 0);
    cout << "starting compare..." << endl;
    std::chrono::steady_clock::time_point t_before_cmp = std::chrono::steady_clock::now();
    compare32Bits(ctNum1, ctNum2, &cc, res);
    std::chrono::steady_clock::time_point t_after_cmp = std::chrono::steady_clock::now();
    std::chrono::duration<double> time_used_for_cmp = std::chrono::duration_cast<std::chrono::duration<double>>(t_after_cmp - t_before_cmp);
    cout << "time used for cmp is: " << time_used_for_cmp.count() << endl;
    
    LWEPlaintext resultcmp;

    cc.Decrypt(sk, res, &resultcmp);

    std::cout << "Result of ... = " << resultcmp << std::endl;

    printBits32(byte1);
    printBits32(byte2);
    
    cout << "phase 1..." << endl;
    int32_t resByte1 = 0x0000;
    int32_t resByte2 = 0x0000;

    for (int i = 31; i >= 0; i--) {
        cc.Decrypt(sk, ctNum1[i], &resultNum1[i]);
        cc.Decrypt(sk, ctNum2[i], &resultNum2[i]);
        resByte1 = resByte1 << 1;
        resByte1 = resByte1 + ((int32_t) (resultNum1[i] & 1));
        resByte2 = resByte2 << 1;
        resByte2 = resByte2 + ((int32_t) (resultNum2[i] & 1));
    }
    cout << "phase 2..." << endl;

    float result1;
    float result2;
    memcpy(&result1, &resByte1, 4);
    memcpy(&result2, &resByte2, 4);
    cout << "result1: " << result1 << endl;
    cout << "result2: " << result2 << endl;
    // Sample Program: Step 4: Evaluation

    // Compute (1 AND 1) = 1; Other binary gate options are OR, NAND, and NOR
    auto ctAND1 = cc.EvalBinGate(AND, ct1, ct2);

    // Compute (NOT 1) = 0
    auto ct2Not = cc.EvalNOT(ct2);

    // Compute (1 AND (NOT 1)) = 0
    auto ctAND2 = cc.EvalBinGate(AND, ct2Not, ct1);

    // Computes OR of the results in ctAND1 and ctAND2 = 1
    auto ctResult = cc.EvalBinGate(OR, ctAND1, ctAND2);

    // Sample Program: Step 5: Decryption

    LWEPlaintext result;

    cc.Decrypt(sk, ctResult, &result);

    std::cout << "Result of ... = " << result << std::endl;

    return 0;
}