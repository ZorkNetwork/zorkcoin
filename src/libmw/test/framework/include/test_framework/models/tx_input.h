
#ifndef BITCOIN_LIBMW_TEST_FRAMEWORK_INCLUDE_TEST_FRAMEWORK_MODELS_TX_INPUT_H
#define BITCOIN_LIBMW_TEST_FRAMEWORK_INCLUDE_TEST_FRAMEWORK_MODELS_TX_INPUT_H
#include <mw/common/macros.h>
#include <mw/models/tx/input.h>
#include <mw/crypto/public_keys.h>

TEST_NAMESPACE

class TxInput
{
public:
    TxInput(const BlindingFactor& blindingFactor, const SecretKey& input_key, const SecretKey& output_key, const uint64_t amount, const Input& input)
        : m_blindingFactor(blindingFactor), m_inputKey(input_key), m_outputKey(output_key), m_amount(amount), m_input(input) {}

    static TxInput Create(
        const BlindingFactor& blindingFactor,
        const SecretKey& input_key,
        const SecretKey& output_key,
        const uint64_t amount)
    {
        mw::Hash output_id = SecretKey::Random().GetBigInt();
        Commitment commitment = Commitment::Blinded(blindingFactor, amount);

        return TxInput(
            blindingFactor,
            input_key,
            output_key,
            amount,
            Input::Create(output_id, commitment, input_key, output_key)
        );
    }

    const BlindingFactor& GetBlindingFactor() const noexcept { return m_blindingFactor; }
    const SecretKey& GetInputKey() const noexcept { return m_inputKey; }
    const SecretKey& GetOutputKey() const noexcept { return m_outputKey; }
    uint64_t GetAmount() const noexcept { return m_amount; }
    const Input& GetInput() const noexcept { return m_input; }

private:
    BlindingFactor m_blindingFactor;
    SecretKey m_inputKey;
    SecretKey m_outputKey;
    uint64_t m_amount;
    Input m_input;
};

END_NAMESPACE
#endif // BITCOIN_LIBMW_TEST_FRAMEWORK_INCLUDE_TEST_FRAMEWORK_MODELS_TX_INPUT_H
