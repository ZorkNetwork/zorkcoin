// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/mwebtests.h>
#include <qt/bitcoinaddressvalidator.h>
#include <qt/guiutil.h>
#include <qt/sendcoinsrecipient.h>
#include <bech32.h>
#include <kernel/chainparams.h>
#include <key_io.h>
#include <mw/models/wallet/stealth_address.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <string>

void MWEBTests::mwebUriTests()
{
    BasicTestingSetup setup{ChainType::REGTEST};
    const QString address = QString::fromStdString(EncodeDestination(CTxDestination{StealthAddress::Random()}));
    QVERIFY(address.startsWith(QString::fromStdString(Params().MWEB_HRP())));

    SendCoinsRecipient info(address, QStringLiteral("mweb-label"), 0, QStringLiteral("mweb-msg"));
    const QString uri = GUIUtil::formatBitcoinURI(info);
    QVERIFY(uri.startsWith(QStringLiteral("zorkcoin:") + address.toUpper()));

    SendCoinsRecipient parsed;
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &parsed));
    QCOMPARE(parsed.address.toLower(), address.toLower());
    QCOMPARE(parsed.label, QStringLiteral("mweb-label"));

    // A URI carrying another chain's MWEB address parses, but the GUI refuses the address.
    BitcoinAddressCheckValidator validator(nullptr);
    int pos{0};
    QCOMPARE(validator.validate(parsed.address, pos), QValidator::Acceptable);
    const bech32::DecodeResult dec = bech32::Decode(address.toStdString(), bech32::CharLimit::MWEB);
    QVERIFY(dec.encoding == bech32::Encoding::BECH32);
    for (const std::string hrp : {"ltcmweb", "mweb", "rmweb", "bc1m", "tb1m", "bcrt1m"}) {
        const QString foreign = QString::fromStdString(bech32::Encode(bech32::Encoding::BECH32, hrp, dec.data));
        SendCoinsRecipient foreign_parsed;
        QVERIFY(GUIUtil::parseBitcoinURI(QStringLiteral("zorkcoin:") + foreign, &foreign_parsed));
        QCOMPARE(foreign_parsed.address, foreign);
        QCOMPARE(validator.validate(foreign_parsed.address, pos), QValidator::Invalid);
    }
}
