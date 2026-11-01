// C++ twin of examples/synthetic/repeated_rotations.py: an ordinary OpenFHE
// program with no CipherScope include, macro, or wrapper. It rotates one
// ciphertext by 1, 2 and 3 and sums the results; rotation key 5 is generated but
// never used. The expected diagnoses are the same as for the Python program.
#include "openfhe.h"

#include <cmath>
#include <iostream>
#include <vector>

using namespace lbcrypto;

int main() {
    const uint32_t batch = 8;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(batch);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto keys = cc->KeyGen();
    // Keys for 1, 2, 3 (used) and 5 (never used in this run).
    cc->EvalRotateKeyGen(keys.secretKey, {1, 2, 3, 5});

    std::vector<double> data = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};
    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(data);
    auto ciph = cc->Encrypt(keys.publicKey, plaintext);

    auto rotated_1 = cc->EvalRotate(ciph, 1);
    auto rotated_2 = cc->EvalRotate(ciph, 2);
    auto rotated_3 = cc->EvalRotate(ciph, 3);
    auto combined = cc->EvalAdd(cc->EvalAdd(rotated_1, rotated_2), rotated_3);

    Plaintext result;
    cc->Decrypt(keys.secretKey, combined, &result);
    result->SetLength(batch);
    auto observed = result->GetRealPackedValue();

    std::cout << "Sum of rotations by 1, 2, 3 of one ciphertext\nobserved:";
    for (uint32_t i = 0; i < batch; ++i) std::cout << " " << std::round(observed[i] * 10000) / 10000;
    std::cout << "\nexpected:";
    for (uint32_t i = 0; i < batch; ++i)
        std::cout << " " << data[(i + 1) % batch] + data[(i + 2) % batch] + data[(i + 3) % batch];
    std::cout << std::endl;
    return 0;
}
