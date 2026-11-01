// BGV: integer packed arithmetic including a vector composite. Declared
// parameters name the scheme (BGVRNS) and plaintext modulus; the trace must
// report scheme BGV and available_slots == ring_dimension.
// Expected canonical events: KeyGen, EvalMultKeyGen, MakePackedPlaintext x3,
//   Encrypt x3, EvalAddMany (3 inputs), EvalMult, EvalNegate, EvalSub, Decrypt.
#include "openfhe.h"

#include <iostream>
#include <vector>

using namespace lbcrypto;

int main() {
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    std::vector<int64_t> x = {1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<int64_t> y = {8, 7, 6, 5, 4, 3, 2, 1};
    std::vector<int64_t> z = {1, 1, 1, 1, 1, 1, 1, 1};
    auto a = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext(x));
    auto b = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext(y));
    auto c = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext(z));

    std::vector<Ciphertext<DCRTPoly>> many = {a, b, c};
    auto sum = cc->EvalAddMany(many);       // 10 everywhere
    auto product = cc->EvalMult(a, b);      // 8, 14, 18, ...
    auto negated = cc->EvalNegate(c);       // -1
    auto result = cc->EvalSub(product, negated);  // product + 1
    auto total = cc->EvalSub(result, sum);        // product + 1 - 10

    Plaintext out;
    cc->Decrypt(keys.secretKey, total, &out);
    out->SetLength(8);
    // total[1] = 14 + 1 - 10 = 5
    std::cout << "total[1] = " << out->GetPackedValue()[1] << " (expected 5)" << std::endl;
    return 0;
}
