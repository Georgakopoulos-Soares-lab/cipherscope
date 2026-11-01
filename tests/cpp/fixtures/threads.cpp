// Concurrent semantic operations on distinct ciphertexts from OpenMP threads.
// Expected: one EvalAdd event per iteration, thread IDs from more than one
// thread when OMP_NUM_THREADS > 1, every event with complete lineage.
#include "openfhe.h"

#include <iostream>
#include <vector>

#include <omp.h>

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

    const int n = 8;
    std::vector<Ciphertext<DCRTPoly>> inputs(n), outputs(n);
    for (int i = 0; i < n; ++i) {
        std::vector<double> x(8, static_cast<double>(i));
        inputs[i] = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(x));
    }
#pragma omp parallel for
    for (int i = 0; i < n; ++i) {
        outputs[i] = cc->EvalAdd(inputs[i], inputs[i]);
    }
    double total = 0;
    for (int i = 0; i < n; ++i) {
        Plaintext out;
        cc->Decrypt(keys.secretKey, outputs[i], &out);
        out->SetLength(8);
        total += out->GetRealPackedValue()[0];
    }
    std::cout << "threads=" << omp_get_max_threads() << " total=" << static_cast<int>(total + 0.5) << " (expected 56)" << std::endl;
    return 0;
}
