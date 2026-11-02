// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <mw/crypto/bulletproofs.h>
#include <mw/crypto/key_derivation.h>
#include <mw/models/tx/mutable_tx.h>
#include <mw/models/wallet/stealth_address.h>
#include <mw/wallet/sign.h>
#include <mweb/mweb_node.h>
#include <primitives/transaction.h>
#include <script/standard.h>

#include <test_framework/test_mweb.h>

#include <set>

BOOST_FIXTURE_TEST_SUITE(TestSign, MWEBTestingSetup)

namespace {

util::Result<SecretKey> RandomSenderKey()
{
    return SecretKey::Random();
}

void CheckValid(const CMutableTransaction& tx)
{
    const CTransaction final_tx(tx);
    BOOST_REQUIRE(final_tx.HasMWEBTx());
    TxValidationState state;
    BOOST_CHECK_MESSAGE(MWEB::Node::CheckTransaction(final_tx, state), state.ToString());
}

void CheckPegInScriptsMatchKernelIDs(const CMutableTransaction& tx)
{
    std::set<mw::Hash> output_kernel_ids;
    for (const CTxOut& out : tx.vout) {
        mw::Hash kernel_id;
        BOOST_REQUIRE(out.scriptPubKey.IsMWEBPegin(&kernel_id));
        output_kernel_ids.insert(kernel_id);
    }

    BOOST_REQUIRE_EQUAL(output_kernel_ids.size(), tx.mweb_tx.kernels.size());
    for (const mw::MutableKernel& kernel : tx.mweb_tx.kernels) {
        const std::optional<mw::Hash> kernel_id = kernel.GetKernelID();
        BOOST_REQUIRE(kernel_id.has_value());
        BOOST_CHECK_EQUAL(output_kernel_ids.count(*kernel_id), 1U);
    }

    CheckValid(tx);
}

//! A receiver with known master keys and one coin at subaddress 0.
struct OwnedCoin {
    SecretKey scan{SecretKey::Random()};
    SecretKey spend{SecretKey::Random()};
    CAmount amount;
    Output output;
    SecretKey shared_secret;
    SecretKey output_spend_key;

    explicit OwnedCoin(CAmount amount_) : amount(amount_)
    {
        const StealthAddress address = mw::DeriveSubaddress(PublicKey::From(spend), scan, 0);
        BlindingFactor blind;
        output = Output::Create(&blind, SecretKey::Random(), address, amount);
        shared_secret = mw::RecoverSharedSecret(output.GetKeyExchangePubKey(), scan);
        output_spend_key = mw::DeriveOutputSpendKey(mw::DeriveSubaddressSpendKey(spend, scan, 0), shared_secret);
    }

    mw::MutableInput Input() const
    {
        mw::MutableInput input = mw::MutableInput::FromOutput(output);
        input.amount = amount;
        input.spend_key = output_spend_key;
        input.shared_secret = shared_secret;
        return input;
    }
};

//! Signs tx and returns the error message, or an empty string on success.
std::string SignError(CMutableTransaction& tx, const mw::SenderKeyGenerator& generator = RandomSenderKey)
{
    const auto result = mw::SignTx(tx, SecretKey::Random(), generator);
    return result ? std::string{} : util::ErrorString(result).original;
}

mw::MutableOutput Recipient(CAmount amount, const StealthAddress& address = StealthAddress::Random())
{
    mw::MutableOutput output;
    output.amount = amount;
    output.address = address;
    return output;
}

} // namespace

BOOST_AUTO_TEST_CASE(MultiplePegInsSameAmount)
{
    static constexpr CAmount PEG_IN_AMOUNT{10'000'000};

    CMutableTransaction tx;
    tx.vout = {
        CTxOut{PEG_IN_AMOUNT, GetScriptForPegin(mw::Hash{})},
        CTxOut{PEG_IN_AMOUNT, GetScriptForPegin(mw::Hash{})}
    };

    for (size_t i = 0; i < 2; ++i) {
        tx.mweb_tx.outputs.push_back(Recipient(PEG_IN_AMOUNT));

        mw::MutableKernel kernel;
        kernel.pegin = PEG_IN_AMOUNT;
        tx.mweb_tx.kernels.push_back(std::move(kernel));
    }

    const auto sign_result = mw::SignTx(tx, SecretKey::Random(), RandomSenderKey);
    BOOST_REQUIRE(sign_result);
    BOOST_CHECK_EQUAL(sign_result->coins_by_output_id.size(), 2U);

    CheckPegInScriptsMatchKernelIDs(tx);
}

BOOST_AUTO_TEST_CASE(SpendInputWithChangeAndFee)
{
    const OwnedCoin coin(5'000'000);
    const SecretKey rewind_key = SecretKey::Random();
    const StealthAddress change_address = StealthAddress::Random();

    CMutableTransaction tx;
    tx.mweb_tx.inputs.push_back(coin.Input());
    tx.mweb_tx.outputs.push_back(Recipient(3'000'000));
    tx.mweb_tx.outputs.push_back(Recipient(1'990'000, change_address));
    tx.mweb_tx.SetFee(10'000);

    std::vector<SecretKey> sender_keys;
    const auto sign_result = mw::SignTx(tx, rewind_key, [&]() -> util::Result<SecretKey> {
        sender_keys.push_back(SecretKey::Random());
        return sender_keys.back();
    });
    BOOST_REQUIRE_MESSAGE(sign_result, util::ErrorString(sign_result).original);
    BOOST_REQUIRE(tx.mweb_tx.IsFinal());
    CheckValid(tx);

    BOOST_REQUIRE_EQUAL(sender_keys.size(), 2U);
    BOOST_REQUIRE_EQUAL(sign_result->coins_by_output_id.size(), 2U);
    for (const mw::MutableOutput& output : tx.mweb_tx.outputs) {
        const mw::Coin& signed_coin = sign_result->coins_by_output_id.at(*output.CalcOutputID());
        BOOST_CHECK_EQUAL(signed_coin.amount, *output.amount);
        BOOST_CHECK(*signed_coin.address == *output.address);
        BOOST_REQUIRE(signed_coin.blind);
        BOOST_CHECK(Commitment::Switch(*signed_coin.blind, signed_coin.amount) == *output.commitment);
        BOOST_CHECK(std::find(sender_keys.begin(), sender_keys.end(), *signed_coin.sender_key) != sender_keys.end());
    }

    const mw::MutableInput& input = tx.mweb_tx.inputs.front();
    BOOST_CHECK(*input.output_pubkey == coin.output.GetReceiverPubKey());
    BOOST_CHECK(*input.commitment == coin.output.GetCommitment());
    BOOST_CHECK_EQUAL(*input.features, Input::STEALTH_KEY_FEATURE_BIT);
}

BOOST_AUTO_TEST_CASE(PegOutKernel)
{
    const OwnedCoin coin(2'000'000);

    CMutableTransaction tx;
    tx.mweb_tx.inputs.push_back(coin.Input());
    tx.mweb_tx.AddPegout(CScript() << OP_TRUE, 1'500'000, false);
    tx.mweb_tx.outputs.push_back(Recipient(480'000));
    tx.mweb_tx.SetFee(20'000);

    const auto sign_result = mw::SignTx(tx, SecretKey::Random(), RandomSenderKey);
    BOOST_REQUIRE_MESSAGE(sign_result, util::ErrorString(sign_result).original);
    CheckValid(tx);
    BOOST_CHECK_EQUAL(CTransaction(tx).mweb_tx.GetPegOuts().size(), 1U);
}

BOOST_AUTO_TEST_CASE(ExtraDataIsCommitted)
{
    const OwnedCoin coin(1'000'000);

    CMutableTransaction tx;
    mw::MutableInput input = coin.Input();
    input.extradata = {0x01, 0x02};
    tx.mweb_tx.inputs.push_back(input);
    mw::MutableOutput output = Recipient(990'000);
    output.message = OutputMessage(OutputMessage::STANDARD_FIELDS_FEATURE_BIT | OutputMessage::EXTRA_DATA_FEATURE_BIT, std::nullopt, {0x03});
    tx.mweb_tx.outputs.push_back(output);
    tx.mweb_tx.SetFee(10'000);
    tx.mweb_tx.kernels.front().extradata = {0x04};

    const auto sign_result = mw::SignTx(tx, SecretKey::Random(), RandomSenderKey);
    BOOST_REQUIRE_MESSAGE(sign_result, util::ErrorString(sign_result).original);
    CheckValid(tx);

    const CTransaction final_tx(tx);
    BOOST_CHECK(final_tx.mweb_tx.m_transaction->GetInputs().front().GetFeatures() & Input::EXTRA_DATA_FEATURE_BIT);
    BOOST_CHECK(final_tx.mweb_tx.m_transaction->GetOutputs().front().GetExtraData() == std::vector<uint8_t>{0x03});
    BOOST_CHECK(final_tx.mweb_tx.m_transaction->GetKernels().front().GetExtraData() == std::vector<uint8_t>{0x04});
}

BOOST_AUTO_TEST_CASE(OutputsAreRewindable)
{
    const SecretKey rewind_key = SecretKey::Random();
    CMutableTransaction tx;
    tx.vout = {CTxOut{1'000'000, GetScriptForPegin(mw::Hash{})}};
    tx.mweb_tx.outputs.push_back(Recipient(1'000'000));
    tx.mweb_tx.SetPeginAmount(1'000'000);

    const auto sign_result = mw::SignTx(tx, rewind_key, RandomSenderKey);
    BOOST_REQUIRE(sign_result);

    const mw::MutableOutput& output = tx.mweb_tx.outputs.front();
    const mw::Coin& coin = sign_result->coins_by_output_id.at(*output.CalcOutputID());
    const SecretKey shared_secret = mw::DeriveSharedSecret(*coin.sender_key, *output.address, *output.amount);
    const std::vector<uint8_t> proof_extra = output.message->Serialized();
    BOOST_CHECK(Bulletproofs::RewindMessage(*output.commitment, **output.proof, proof_extra, mw::DeriveProofNonce(rewind_key, *output.commitment)) == shared_secret.GetBigInt());
    BOOST_CHECK(Bulletproofs::RewindMessage(*output.commitment, **output.proof, proof_extra, mw::DeriveProofNonce(SecretKey::Random(), *output.commitment)) != shared_secret.GetBigInt());
}

BOOST_AUTO_TEST_CASE(FailuresLeaveTransactionUnchanged)
{
    const OwnedCoin coin(1'000'000);

    CMutableTransaction tx;
    mw::MutableInput input = coin.Input();
    input.spend_key.reset();
    tx.mweb_tx.inputs.push_back(input);
    tx.mweb_tx.outputs.push_back(Recipient(990'000));
    tx.mweb_tx.SetFee(10'000);

    const CMutableTransaction before{tx};
    const auto sign_result = mw::SignTx(tx, SecretKey::Random(), RandomSenderKey);
    BOOST_REQUIRE(!sign_result);
    BOOST_CHECK_EQUAL(util::ErrorString(sign_result).original, "Input spend key missing");
    BOOST_CHECK(tx.mweb_tx == before.mweb_tx);
}

BOOST_AUTO_TEST_CASE(InputRejections)
{
    const OwnedCoin coin(1'000'000);

    const auto sign_with = [&](const mw::MutableInput& input) {
        CMutableTransaction tx;
        tx.mweb_tx.inputs.push_back(input);
        tx.mweb_tx.outputs.push_back(Recipient(990'000));
        tx.mweb_tx.SetFee(10'000);
        const auto result = mw::SignTx(tx, SecretKey::Random(), RandomSenderKey);
        return result ? std::string{} : util::ErrorString(result).original;
    };

    BOOST_CHECK_EQUAL(sign_with(coin.Input()), "");

    mw::MutableInput wrong_key = coin.Input();
    wrong_key.spend_key = SecretKey::Random();
    BOOST_CHECK_EQUAL(sign_with(wrong_key), "Input spend key does not match output pubkey");

    mw::MutableInput wrong_amount = coin.Input();
    wrong_amount.amount = coin.amount + 1;
    BOOST_CHECK_EQUAL(sign_with(wrong_amount), "Input amount or blinding factor does not match commitment");

    mw::MutableInput no_blind = coin.Input();
    no_blind.shared_secret.reset();
    BOOST_CHECK_EQUAL(sign_with(no_blind), "Input blinding factor and shared secret missing");

    mw::MutableInput no_amount = coin.Input();
    no_amount.amount.reset();
    BOOST_CHECK_EQUAL(sign_with(no_amount), "Input amount missing");

    mw::MutableInput no_stealth = coin.Input();
    no_stealth.features = 0;
    BOOST_CHECK_EQUAL(sign_with(no_stealth), "Input does not have the stealth key feature");

    mw::MutableInput missing_extra = coin.Input();
    missing_extra.features = Input::STEALTH_KEY_FEATURE_BIT | Input::EXTRA_DATA_FEATURE_BIT;
    BOOST_CHECK_EQUAL(sign_with(missing_extra), "Input extra data missing");

    mw::MutableInput unbalanced = coin.Input();
    unbalanced.amount = coin.amount;
    CMutableTransaction tx;
    tx.mweb_tx.inputs.push_back(unbalanced);
    tx.mweb_tx.outputs.push_back(Recipient(coin.amount));
    tx.mweb_tx.SetFee(10'000);
    const auto result = mw::SignTx(tx, SecretKey::Random(), RandomSenderKey);
    BOOST_REQUIRE(!result);
    BOOST_CHECK(util::ErrorString(result).original.starts_with("Validate failed"));
}

BOOST_AUTO_TEST_CASE(OutputAndGeneratorRejections)
{
    CMutableTransaction tx;
    tx.vout = {CTxOut{1'000'000, GetScriptForPegin(mw::Hash{})}};
    tx.mweb_tx.outputs.push_back(Recipient(1'000'000));
    tx.mweb_tx.SetPeginAmount(1'000'000);

    BOOST_CHECK_EQUAL(SignError(tx, nullptr), "Sender key generator missing");
    BOOST_CHECK_EQUAL(SignError(tx, []() -> util::Result<SecretKey> { return util::Error{Untranslated("locked")}; }), "locked");

    CMutableTransaction no_address{tx};
    no_address.mweb_tx.outputs.front().address.reset();
    BOOST_CHECK_EQUAL(SignError(no_address), "Output amount or address missing");

    CMutableTransaction missing_extra{tx};
    missing_extra.mweb_tx.outputs.front().message = OutputMessage(OutputMessage::STANDARD_FIELDS_FEATURE_BIT | OutputMessage::EXTRA_DATA_FEATURE_BIT, std::nullopt, {});
    BOOST_CHECK_EQUAL(SignError(missing_extra), "Output extra data missing");
}

BOOST_AUTO_TEST_CASE(PegInScriptRejections)
{
    CMutableTransaction base;
    base.mweb_tx.outputs.push_back(Recipient(1'000'000));
    base.mweb_tx.SetPeginAmount(1'000'000);

    CMutableTransaction missing_output{base};
    BOOST_CHECK_EQUAL(SignError(missing_output), "Peg-in output count does not match MWEB pegin kernel count");

    CMutableTransaction wrong_amount{base};
    wrong_amount.vout = {CTxOut{999'999, GetScriptForPegin(mw::Hash{})}};
    BOOST_CHECK_EQUAL(SignError(wrong_amount), "Peg-in output amount does not match MWEB pegin kernel");

    CMutableTransaction wrong_id{base};
    wrong_id.vout = {CTxOut{1'000'000, GetScriptForPegin(SecretKey::Random().GetBigInt())}};
    BOOST_CHECK_EQUAL(SignError(wrong_id), "Peg-in output kernel ID conflicts with MWEB pegin kernel order");
    BOOST_CHECK(wrong_id.mweb_tx == base.mweb_tx);
}

BOOST_AUTO_TEST_CASE(FinalOrNullTransactionIsNoop)
{
    CMutableTransaction empty;
    const auto empty_result = mw::SignTx(empty, SecretKey::Random(), nullptr);
    BOOST_REQUIRE(empty_result);
    BOOST_CHECK(empty_result->coins_by_output_id.empty());

    CMutableTransaction tx;
    tx.vout = {CTxOut{1'000'000, GetScriptForPegin(mw::Hash{})}};
    tx.mweb_tx.outputs.push_back(Recipient(1'000'000));
    tx.mweb_tx.SetPeginAmount(1'000'000);
    BOOST_REQUIRE_EQUAL(SignError(tx), "");

    const CMutableTransaction signed_tx{tx};
    const auto result = mw::SignTx(tx, SecretKey::Random(), RandomSenderKey);
    BOOST_REQUIRE(result);
    BOOST_CHECK(result->coins_by_output_id.empty());
    BOOST_CHECK(tx.mweb_tx == signed_tx.mweb_tx);
    BOOST_CHECK(tx.vout == signed_tx.vout);
}

BOOST_AUTO_TEST_SUITE_END()
