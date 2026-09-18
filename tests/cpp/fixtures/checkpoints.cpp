// Opt-in annotations and precision checkpoints through cipherscope/annotate.h.
// The header's calls are inline no-ops unless the unit is compiled through the
// CipherScope launcher: this program builds and runs without CipherScope
// (nothing is decrypted), and under `cipherscope profile` the runtime records
// them as `annotation` / `checkpoint` events at these source lines.
// Expected canonical events: KeyGen, EvalMultKeyGen, MakeCKKSPackedPlaintext,
//   AnnotatePlaintext, MakeCKKSPackedPlaintext, AnnotatePlaintext, Encrypt,
//   Annotate, PrecisionCheckpoint "fresh", Encrypt, Annotate (provenance),
//   EvalMult ct_ct, EvalSquare x3, PrecisionCheckpoint "after_three_squarings"
//   (tolerance min_bits 40 -> violated), Decrypt.
#include "openfhe.h"

#include "cipherscope/annotate.h"

#include <iostream>
#include <vector>

using namespace lbcrypto;

int main() {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(6);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(4);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    std::vector<double> data = {1.5, 2.0, 2.5, 3.0};
    std::vector<double> weights = {1.0, 1.0, 1.0, 1.0};
    Plaintext pw1 = cc->MakeCKKSPackedPlaintext(weights);
    cipherscope::annotate_plaintext(pw1, "model_parameter", "layer0");
    Plaintext pw2 = cc->MakeCKKSPackedPlaintext(weights);       // the same public constant encoded twice
    cipherscope::annotate_plaintext(pw2, "model_parameter", "layer0");

    auto ciph = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(data));
    cipherscope::annotate(ciph, {{4}, "row_major", 4, ""});    // 4 meaningful slots of N/2 available
    cipherscope::checkpoint("fresh", cc, ciph, keys.secretKey, data);

    auto encrypted_weights = cc->Encrypt(keys.publicKey, pw1);
    cipherscope::annotate(encrypted_weights, {{}, "", -1, "model_parameter"});  // a public value, encrypted
    auto scaled = cc->EvalMult(ciph, encrypted_weights);       // ct * ct on a public operand

    std::vector<double> current = data;
    for (int i = 0; i < 3; ++i) {
        scaled = cc->EvalSquare(scaled);
        for (double& value : current) value *= value;
    }
    cipherscope::Tolerance tolerance;
    tolerance.min_bits = 40.0;                                  // far more than CKKS keeps at these magnitudes
    cipherscope::checkpoint("after_three_squarings", cc, scaled, keys.secretKey, current, tolerance);

    Plaintext out;
    cc->Decrypt(keys.secretKey, scaled, &out);
    out->SetLength(4);
    auto values = out->GetRealPackedValue();
    // Same output with and without CipherScope: the header adds no behaviour a
    // plain build could observe.
    std::cout << "result[3] = " << static_cast<long>(values[3] + 0.5) << " (expected " << static_cast<long>(current[3]) << ")" << std::endl;
    return 0;
}
