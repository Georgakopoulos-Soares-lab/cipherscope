// Vector-input composites, a Chebyshev series and the EvalAtIndex alias.
// Expected canonical events (one per user-level call):
//   KeyGen, EvalMultKeyGen, EvalRotateKeyGen (spelled EvalAtIndexKeyGen),
//   MakeCKKSPackedPlaintext x3, Encrypt x3,
//   EvalAddMany (3 inputs), EvalMultMany (3 inputs), EvalLinearWSum (3 inputs),
//   EvalChebyshevSeries (degree 3), EvalRotate (spelled EvalAtIndex), EvalAdd, Decrypt.
#include "openfhe.h"

#include <iostream>
#include <vector>

using namespace lbcrypto;

int main() {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(6);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(8);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalAtIndexKeyGen(keys.secretKey, {1});   // alias of EvalRotateKeyGen

    std::vector<double> x = {1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<double> y = {8, 7, 6, 5, 4, 3, 2, 1};
    std::vector<double> z = {1, 1, 1, 1, 1, 1, 1, 1};
    auto a = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(x));
    auto b = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(y));
    auto c = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(z));

    std::vector<Ciphertext<DCRTPoly>> many = {a, b, c};
    auto sum = cc->EvalAddMany(many);                       // a + b + c
    auto product = cc->EvalMultMany(many);                  // a * b * c
    std::vector<ReadOnlyCiphertext<DCRTPoly>> views(many.begin(), many.end());
    std::vector<double> weights = {0.5, 0.25, 0.25};
    auto weighted = cc->EvalLinearWSum(views, weights);     // 0.5a + 0.25b + 0.25c
    std::vector<double> coefficients = {0.5, 0.25, 0.125, 0.0625};
    auto series = cc->EvalChebyshevSeries(a, coefficients, -8.0, 8.0);  // degree 3
    auto rotated = cc->EvalAtIndex(sum, 1);                 // alias of EvalRotate
    auto total = cc->EvalAdd(rotated, product);

    Plaintext out;
    cc->Decrypt(keys.secretKey, total, &out);
    out->SetLength(8);
    auto values = out->GetRealPackedValue();
    // rotated[0] = sum[1] = 2 + 7 + 1 = 10; product[0] = 1 * 8 * 1 = 8
    std::cout << "total[0] = " << static_cast<int>(values[0] + 0.5) << " (expected 18)" << std::endl;
    cc->Decrypt(keys.secretKey, weighted, &out);
    out->SetLength(8);
    std::cout << "weighted[0] = " << static_cast<int>(out->GetRealPackedValue()[0] * 4 + 0.5) << "/4 (expected 11/4)" << std::endl;
    return 0;
}
