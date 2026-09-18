// Handle copies, moves, container storage and address reuse.
// Expected: `auto b = a;` does not create a second ciphertext identity; the
// EvalAdd(a, b) event names one input; ciphertexts created in a loop and
// destroyed each iteration get distinct IDs (no address inherits an old ID);
// the final number of distinct ciphertext identities equals the number of
// ciphertext-producing operations.
#include "openfhe.h"

#include <iostream>
#include <utility>
#include <vector>

using namespace lbcrypto;

int main() {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(8);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    auto keys = cc->KeyGen();

    std::vector<double> x = {1, 2, 3, 4, 5, 6, 7, 8};
    auto a = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(x));   // Encrypt -> identity 1
    auto b = a;                                                                // copy of the handle: same identity
    auto sum = cc->EvalAdd(a, b);                                              // one distinct input, identity 2

    std::vector<Ciphertext<DCRTPoly>> kept;
    kept.push_back(std::move(sum));                                            // move keeps identity 2
    auto again = cc->EvalAdd(kept[0], a);                                      // identity 3

    for (int i = 0; i < 3; ++i) {
        auto temporary = cc->EvalAdd(a, a);                                    // identities 4, 5, 6 -- destroyed each iteration
        (void)temporary;
    }
    auto last = cc->EvalAdd(again, a);                                         // identity 7

    Plaintext out;
    cc->Decrypt(keys.secretKey, last, &out);
    out->SetLength(8);
    std::cout << "last[0] = " << static_cast<int>(out->GetRealPackedValue()[0] + 0.5) << " (expected 4)" << std::endl;
    return 0;
}
