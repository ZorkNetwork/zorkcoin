#include <test_framework/models/tx.h>
#include <test_framework/tx_builder.h>
#include <mw/crypto/blinds.h>
#include <mw/crypto/secret_keys.h>
#include <mw/crypto/pedersen.h>

test::Tx test::Tx::CreatePegIn(const CAmount amount, const CAmount fee)
{
    return test::TxBuilder()
        .AddPeginKernel(amount, fee)
        .AddOutput(amount)
        .Build();
}

test::Tx test::Tx::CreatePegOut(const test::TxOutput& input, const CAmount fee)
{
    return test::TxBuilder()
        .AddInput(input)
        .AddPegoutKernel(input.GetAmount() - fee, fee, true)
        .Build();
}
