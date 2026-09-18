// C++ twin of evaluation/scaling/kernel.py's workload: N semantic operations in
// a fixed mix (EvalAdd, EvalSub, EvalRotate, EvalAdd) on a depth-1 CKKS
// context. Prints one JSON line with the loop's wall time so the native
// overhead study can compare a plain build with an instrumented one.
//   scaling_kernel <N>
#include "openfhe.h"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <vector>

using namespace lbcrypto;

int main(int argc, char** argv) {
    const long n = argc > 1 ? std::atol(argv[1]) : 1000;
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
    std::vector<double> data = {1, 2, 3, 4, 5, 6, 7, 8};

    auto started = std::chrono::steady_clock::now();
    auto left = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(data));
    auto right = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(data));
    auto accumulator = left;
    for (long index = 0; index < n; ++index) {
        switch (index % 4) {
            case 0: accumulator = cc->EvalAdd(accumulator, right); break;
            case 1: accumulator = cc->EvalSub(accumulator, right); break;
            case 2: accumulator = cc->EvalRotate(accumulator, 1); break;
            default: accumulator = cc->EvalAdd(left, right); break;
        }
    }
    auto elapsed = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
    std::cout << "{\"size\": " << n << ", \"loop_ms\": " << elapsed << "}" << std::endl;
    return 0;
}
