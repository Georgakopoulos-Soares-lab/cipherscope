// Uses a CryptoContext member the operation manifest does not cover
// (EvalSumRowsKeyGen / EvalSumRows). Strict tracing must not claim
// COMPLETE coverage: the run is PARTIAL-PERMISSIVE and names the calls.
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
    cc->Enable(ADVANCEDSHE);
    auto keys = cc->KeyGen();
    auto rowKeys = cc->EvalSumRowsKeyGen(keys.secretKey, nullptr, 2);   // not in the manifest

    std::vector<double> x = {1, 2, 3, 4, 5, 6, 7, 8};
    auto a = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(x));
    auto sums = cc->EvalSumRows(a, 2, *rowKeys);                         // not in the manifest
    auto b = cc->EvalAdd(a, sums);
    Plaintext out;
    cc->Decrypt(keys.secretKey, b, &out);
    out->SetLength(8);
    std::cout << "b[0] = " << static_cast<int>(out->GetRealPackedValue()[0] + 0.5) << std::endl;
    return 0;
}
