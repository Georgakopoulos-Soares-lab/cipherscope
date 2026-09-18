// Operator overloads, in-place mutation and ciphertext-plaintext multiply.
// Expected canonical events (one per user-level call, nothing duplicated):
//   KeyGen, EvalMultKeyGen, MakeCKKSPackedPlaintext x3, Encrypt x2,
//   EvalMult ct_ct (a * b), EvalAdd ct_ct (a + b), EvalAdd ct_ct (c += d),
//   EvalAddInPlace (d:v0 -> d:v1), RescaleInPlace (c -> next version),
//   EvalNegate (-a), EvalMult ct_pt (a * plaintext), Decrypt.
#include "openfhe.h"

#include <iostream>
#include <vector>

using namespace lbcrypto;

int main() {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(3);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(8);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    std::vector<double> x = {1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<double> y = {8, 7, 6, 5, 4, 3, 2, 1};
    std::vector<double> w = {0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5};
    Plaintext px = cc->MakeCKKSPackedPlaintext(x);
    Plaintext py = cc->MakeCKKSPackedPlaintext(y);
    Plaintext pw = cc->MakeCKKSPackedPlaintext(w);
    auto a = cc->Encrypt(keys.publicKey, px);
    auto b = cc->Encrypt(keys.publicKey, py);

    auto c = a * b;                 // operator* -> EvalMult ct_ct
    auto d = a + b;                 // operator+ -> EvalAdd ct_ct
    c += d;                         // operator+= -> EvalAdd ct_ct (new object assigned to c)
    cc->EvalAddInPlace(d, a);       // in place: d gains a version
    cc->RescaleInPlace(c);          // in place: c gains a version
    auto e = -a;                    // unary operator- -> EvalNegate
    auto f = cc->EvalMult(a, pw);   // EvalMult ct_pt

    Plaintext out;
    cc->Decrypt(keys.secretKey, c, &out);
    out->SetLength(8);
    auto values = out->GetRealPackedValue();
    std::cout << "c[0] = " << static_cast<int>(values[0] + 0.5) << " (expected " << (1 * 8 + 1 + 8) << ")" << std::endl;
    return 0;
}
