// BFV: integer packed arithmetic with rotation. Declared parameters name the
// scheme (BFVRNS) and plaintext modulus; the trace must report scheme BFV,
// available_slots == ring_dimension and level 0 throughout.
// Expected canonical events: KeyGen, EvalMultKeyGen, EvalRotateKeyGen,
//   MakePackedPlaintext x2, Encrypt x2, EvalAdd, EvalMult, EvalRotate, EvalAdd, EvalSub, Decrypt.
#include "openfhe.h"

#include <iostream>
#include <vector>

using namespace lbcrypto;

int main() {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalRotateKeyGen(keys.secretKey, {1});

    std::vector<int64_t> x = {1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<int64_t> y = {8, 7, 6, 5, 4, 3, 2, 1};
    Plaintext px = cc->MakePackedPlaintext(x);
    Plaintext py = cc->MakePackedPlaintext(y);
    auto a = cc->Encrypt(keys.publicKey, px);
    auto b = cc->Encrypt(keys.publicKey, py);

    auto sum = cc->EvalAdd(a, b);          // 9 everywhere
    auto product = cc->EvalMult(a, b);     // 8, 14, 18, 20, 20, 18, 14, 8
    auto rotated = cc->EvalRotate(product, 1);
    auto total = cc->EvalAdd(sum, rotated);
    auto result = cc->EvalSub(total, a);

    Plaintext out;
    cc->Decrypt(keys.secretKey, result, &out);
    out->SetLength(8);
    // result[0] = 9 + product[1] - a[0] = 9 + 14 - 1 = 22
    std::cout << "result[0] = " << out->GetPackedValue()[0] << " (expected 22)" << std::endl;
    return 0;
}
