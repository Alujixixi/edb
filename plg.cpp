/*
  Simple example for BGVrns (integer arithmetic)
 */

#include "openfhe.h"
#include <random>
#include <chrono>
#include <cmath>
#include <map>

// #include <bitset>
using namespace lbcrypto;
using std::vector;
using std::cout;
using std::endl;

void run_big(const int bigPlaintextModulus, const vector<int64_t> compareVector1, 
                                                const vector<int64_t> compareVector2);

void run_big_coef(const int bigPlaintextModulus, 
                    const vector<int64_t> compareVector1, 
                        const vector<int64_t> compareVector2,
                        const int batchSize);

void run_crt(const int crtModulusVector[], const vector<int64_t> compareVector1[], const vector<int64_t> compareVector2[],
                const int crtModulusNumber, const int batchSize);


int main() {
    std::default_random_engine dre;
    dre.seed(time(0));

    const int batchSize = 12;

    // 2^16
    // const int bigPlaintextModulus = 65537;
    // const int crtModulusVector[] = {41, 43, 37};
    
    // 2^24
    // const int bigPlaintextModulus = 16777259;
    // const int crtModulusVector[] = {61, 67, 71, 73}; 

    // 2^20
    const int bigPlaintextModulus = 1048583;
    const int crtModulusVector[] = {23, 29, 31, 37};

    // 83 89 97
    // 41, 43, 47
    // `MakeCoefPackedPlaintext` can only accept `plaintextModulus / 2`
    // const int crtModulusVector[] = {83, 89, 97};
    
    const int len = sizeof(crtModulusVector) / sizeof(crtModulusVector[0]);
    vector<int64_t> rnsCompareVector1[len];
    vector<int64_t> rnsCompareVector2[len];
    std::uniform_int_distribution<int> u = std::uniform_int_distribution<int>(0, bigPlaintextModulus);

    vector<int64_t> compareVector1;
    vector<int64_t> compareVector2;

    for (int i = 0; i < batchSize; i++) {
        unsigned int num1 = u(dre);
        unsigned int num2 = u(dre);
        compareVector1.push_back(num1);
        compareVector2.push_back((i&1) ? num1 : num2);

        
        for (int j = 0; j < len; j++) {
            int val_1 = (num1 % (crtModulusVector[j])) - crtModulusVector[j]/2;
            int val_2 = (num2 % (crtModulusVector[j])) - crtModulusVector[j]/2;
            rnsCompareVector1[j].push_back(val_1);
            rnsCompareVector2[j].push_back(val_2);
        }
    }

    // float f1 = 1.25f;
    // float f2 = 1.25f;
    // int64_t i1, i2;
    // memcpy(&i1, &f1, sizeof(float));
    // memcpy(&i2, &f2, sizeof(float));
    // vector<int64_t> v1 = {i1};
    // vector<int64_t> v2 = {i2};


    // run_big(bigPlaintextModulus, v1, v2);

    // run_big(bigPlaintextModulus, compareVector1, compareVector2);
    run_big_coef(bigPlaintextModulus, compareVector1, compareVector2, batchSize);
    run_crt(crtModulusVector, rnsCompareVector1, rnsCompareVector2, len, batchSize);

}


void run_big(const int bigPlaintextModulus, const vector<int64_t> compareVector1, 
                                                const vector<int64_t> compareVector2) {

    cout << "Start run_big" << endl;

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetMultiplicativeDepth(16);
    parameters.SetPlaintextModulus(bigPlaintextModulus);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    cout << "\np = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    cout << "m = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() << std::endl;
    std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;
    // cout << "SecurityLevel : " << cryptoContext -> GetSecurityLevel() << endl;

    KeyPair<DCRTPoly> keyPair;
    keyPair = cryptoContext->KeyGen();
    cout << "KenGen Finished" << endl;
    
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(compareVector1);
    cout << "Plaintext1: " << plaintext1 << endl;
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

    Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(compareVector2);
    cout << "Plaintext2: " << plaintext2 << endl;
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

    vector<int64_t> vectorOfInts1 = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    Plaintext plaintextAllOne = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    auto ciphertextAllOne = cryptoContext->Encrypt(keyPair.publicKey, plaintextAllOne);

    auto cp = cryptoContext -> EvalSub(ciphertext1, ciphertext2);

    auto res = ciphertextAllOne;

    cout << "Starting mult..." << endl;
    std::chrono::steady_clock::time_point t_before_mul = std::chrono::steady_clock::now();

    for (int i = bigPlaintextModulus - 1; i > 0; i >>= 1) {
        if(i&1) {
            res = cryptoContext -> EvalMult(cp, res);
        }
        cp = cryptoContext -> EvalMult(cp, cp);
    }
    std::chrono::steady_clock::time_point t_after_mul = std::chrono::steady_clock::now();
    cout << "mult finished..." << endl;

    // Decrypt the result of multiplications
    Plaintext plaintextMultResult;
    cryptoContext->Decrypt(keyPair.secretKey, res, &plaintextMultResult);

    cout << "Plaintext #res: " << plaintextMultResult << endl;

    std::chrono::duration<double> time_used_for_mul = std::chrono::duration_cast<std::chrono::duration<double>>(t_after_mul - t_before_mul);
    cout << "time used for mul is: " << time_used_for_mul.count() << endl;
}


void run_big_coef(const int bigPlaintextModulus, 
                    const vector<int64_t> compareVector1, 
                        const vector<int64_t> compareVector2,
                        const int batchSize) {

    cout << "Start run_big_coef" << endl;
    cout << "compareVector1: " << endl;
    for (int i = 0; i < batchSize; i++) {
        cout << compareVector1[i] << " ";
    }
    cout << endl;

    cout << "compareVector2: " << endl;
    for (int i = 0; i < batchSize; i++) {
        cout << compareVector2[i] << " ";
    }
    cout << endl;

    double multTime = 0.0;

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetMultiplicativeDepth(16);
    // parameters.SetPlaintextModulus(67);
    parameters.SetPlaintextModulus(bigPlaintextModulus);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    cout << "\np = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    cout << "m = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() << std::endl;
    std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;
    // cout << "SecurityLevel : " << cc -> GetSecurityLevel() << endl;

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    cout << "KenGen Finished" << endl;
    
    cc->EvalMultKeyGen(keyPair.secretKey);
    
    for (int i = 0; i < batchSize; i++) {

        vector<int64_t> v(1);
        v[0] = compareVector1[i] - bigPlaintextModulus / 2;
        Plaintext pt1 = cc->MakeCoefPackedPlaintext(v);
        auto ct1 = cc -> Encrypt(keyPair.publicKey, pt1);

        v[0] = compareVector2[i] - bigPlaintextModulus / 2;
        Plaintext pt2 = cc->MakeCoefPackedPlaintext(v);
        auto ct2 = cc -> Encrypt(keyPair.publicKey, pt2);

        vector<int64_t> vectorOfInts1 = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        Plaintext plaintextAllOne = cc->MakeCoefPackedPlaintext(vectorOfInts1);
        auto ciphertextAllOne = cc->Encrypt(keyPair.publicKey, plaintextAllOne);

        auto cp = cc -> EvalSub(ct1, ct2);

        auto res = ciphertextAllOne;

        // cout << "Starting mult..." << endl;
        std::chrono::steady_clock::time_point t_before_mul = std::chrono::steady_clock::now();

        for (int x = bigPlaintextModulus - 1; x > 0; x >>= 1) {
            if(x&1) {
                res = cc -> EvalMult(cp, res);
            }
            cp = cc -> EvalMult(cp, cp);
        }
        std::chrono::steady_clock::time_point t_after_mul = std::chrono::steady_clock::now();
        std::chrono::duration<double> time_used_for_mul = std::chrono::duration_cast<std::chrono::duration<double>>(t_after_mul - t_before_mul);
        multTime += time_used_for_mul.count();
        // cout << "mult finished..." << endl;
    }


    // Decrypt the result of multiplications
    // Plaintext plaintextMultResult;
    // cryptoContext->Decrypt(keyPair.secretKey, res, &plaintextMultResult);

    // cout << "Plaintext #res: " << plaintextMultResult << endl;

    cout << "time used for mul is: " << multTime << endl;
}



void run_crt(const int crtModulusVector[],
                 const vector<int64_t> compareVector1[], 
                    const vector<int64_t> compareVector2[],
                        const int crtModulusNumber, 
                            const int batchSize) {

    
    cout << "starting CRT comparation..." << endl;
    cout << "CRT modulus: " << endl;
    for (int i = 0; i < crtModulusNumber; i++) {
        cout << crtModulusVector[i] << " ";
    }
    cout << endl;
    cout << "compareVector1: " << endl;
    for (int i = 0; i < crtModulusNumber; i++) {
        for (int j = 0; j < batchSize; j++) {
            cout << compareVector1[i][j] << " ";
        }
        cout << endl;
    }
    cout << endl;

    cout << "compareVector2: " << endl;
    for (int i = 0; i < crtModulusNumber; i++) {
        for (int j = 0; j < batchSize; j++) {
            cout << compareVector2[i][j] << " ";
        }
        cout << endl;
    }
    cout << endl;

    using T_CP = Ciphertext<DCRTPoly>;

    // for the ans cp
    vector<vector<T_CP>> resVector(crtModulusNumber, vector<T_CP>(batchSize, 0));

    double multTime = 0.0;

    for (int i = 0; i < crtModulusNumber; i++) {
        const int modulus = crtModulusVector[i];
        CCParams<CryptoContextBFVRNS> parameters;
        parameters.SetMultiplicativeDepth(floor(log2(modulus)));
        // parametersVector[i].SetMultiplicativeDepth(2);
        parameters.SetPlaintextModulus(modulus);
        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        KeyPair<DCRTPoly> keyPair = cc -> KeyGen();
        cc -> EvalMultKeyGen(keyPair.secretKey);

        vector<int64_t> vectorOfInts1 = {1};
        Plaintext plaintextAllOne = cc->MakeCoefPackedPlaintext(vectorOfInts1);
        auto ciphertextAllOne = cc -> Encrypt(keyPair.publicKey, plaintextAllOne);
        
        // i compareVector
        // j nums in compareVector[i]
        for (int j = 0; j < batchSize; j++) {
            // get compareVector[i][j] and handle one number one time
            vector<int64_t> v(1);
            v[0] = compareVector1[i][j];
            Plaintext pt1 = cc->MakeCoefPackedPlaintext(v);
            auto ct1 = cc -> Encrypt(keyPair.publicKey, pt1);

            v[0] = compareVector2[i][j];
            Plaintext pt2 = cc->MakeCoefPackedPlaintext(v);
            auto ct2 = cc -> Encrypt(keyPair.publicKey, pt2);
            auto ct = cc->EvalSub(ct1, ct2);

            Plaintext plaintextResult;
            cc -> Decrypt(keyPair.secretKey, ct, &plaintextResult);
            // cout << "Plaintext ct1 - ct2: " << plaintextResult << endl;

            auto res = ciphertextAllOne;

            // cout << "Starting CRT mult, modulus " << i << "\t batch " << j << endl;
            std::chrono::steady_clock::time_point t_before_mul = std::chrono::steady_clock::now();

            for (int x = modulus - 1; x > 0; x >>= 1) {
                if(x&1) {
                    res = cc -> EvalMult(ct, res);
                }
                ct = cc -> EvalMult(ct, ct);
            }

            // cout << "mult finished..." << endl;
            std::chrono::steady_clock::time_point t_after_mul = std::chrono::steady_clock::now();
            

            std::chrono::duration<double> time_used_for_mul = std::chrono::duration_cast<std::chrono::duration<double>>(t_after_mul - t_before_mul);
            multTime += time_used_for_mul.count();

            resVector[i][j] = res;
        }

        for (int j = 0; j < batchSize; j++) {
            Plaintext plaintextResult;
            cc -> Decrypt(keyPair.secretKey, resVector[i][j], &plaintextResult);
            // cout << "Plaintext #" << j << ": " << plaintextResult << endl;
        }
    }
    cout << "total mul time: " << multTime << endl;
}
