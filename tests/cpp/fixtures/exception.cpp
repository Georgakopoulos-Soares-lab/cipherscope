// A failing OpenFHE call: rotating without the matching rotation key throws.
// The application catches the exception and continues; CipherScope must
// preserve that behaviour, record the failed call as an error event, and keep
// tracing the calls that follow.
#include "openfhe.h"

#include <iostream>
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
    cc->EvalRotateKeyGen(keys.secretKey, {1});

    std::vector<double> x = {1, 2, 3, 4, 5, 6, 7, 8};
    auto a = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(x));
    int caught = 0;
    try {
        auto bad = cc->EvalRotate(a, 4);   // no key for index 4: throws
        (void)bad;
    } catch (const std::exception& error) {
        caught = 1;
    }
    auto good = cc->EvalRotate(a, 1);      // still traced after the failure
    Plaintext out;
    cc->Decrypt(keys.secretKey, good, &out);
    out->SetLength(8);
    std::cout << "caught=" << caught << " good[0]=" << static_cast<int>(out->GetRealPackedValue()[0] + 0.5) << std::endl;
    return caught == 1 ? 0 : 3;
}
