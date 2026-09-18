// Uses CryptoContext members the operation manifest does not cover
// (EvalAddMany / EvalMultMany, the same composites the Python gate's GAP-04
// exercises). Strict tracing must not claim COMPLETE coverage: the run is
// PARTIAL-PERMISSIVE and names the calls.
#include "openfhe.h"

#include <iostream>
#include <vector>

using namespace lbcrypto;

int main() {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(2);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(8);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    std::vector<double> x = {1, 2, 3, 4, 5, 6, 7, 8};
    auto a = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(x));
    auto b = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(x));
    std::vector<Ciphertext<DCRTPoly>> many = {a, b};
    auto sum = cc->EvalAddMany(many);        // not in the manifest
    auto product = cc->EvalMultMany(many);   // not in the manifest
    auto c = cc->EvalAdd(sum, product);
    Plaintext out;
    cc->Decrypt(keys.secretKey, c, &out);
    out->SetLength(8);
    std::cout << "c[0] = " << static_cast<int>(out->GetRealPackedValue()[0] + 0.5) << " (expected 3)" << std::endl;
    return 0;
}
