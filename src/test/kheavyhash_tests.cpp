#include <boost/test/unit_test.hpp>
#include <crypto/kheavyhash.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <string>
#include <iomanip>


BOOST_AUTO_TEST_SUITE(kheavyhash_tests)

static uint256 swap256S(const char *str)
{
    char swapStr[65] = {0};
    for (int i=0; i<32; i++)
    {
        swapStr[  i*2] = str[  62-i*2];
        swapStr[1+i*2] = str[1+62-i*2];
    }
    uint256 rv;
    rv.SetHex(swapStr);
    return rv;
}

BOOST_AUTO_TEST_CASE(kheavyhash_hashtest)
{
    uint256 calculated;
    const char* seedin  = "7a11f1275ca946ff062fa81b39770faa1503327a52f90ae0325ee2ad53f1e7d0";
    uint256 seed = uint256S(seedin);
    const char* hashout = "937477b907a88ddfa23d2ce5d31c6c8d3ca174ec467761e7ee28bc907ac4b89b";
    uint256 spec = uint256S(hashout);

    KHeavyHash testhash = KHeavyHash(seed);
    testhash.Write(seed);
    testhash.Finalize(calculated);
    BOOST_CHECK(calculated == spec);

    const char* seedin2  = "1b2f5a8c916d543d3b7e844ba5de2d76eb434bffadb123a853f0ac8873c74108";
    seed = uint256S(seedin2);
    const char* hashout2 = "d33e2737b5fcf51882bea0bdd178bbe46afd958b755a919fcf549f535209173a";
    spec = uint256S(hashout2);

    testhash.Reset(seed);
    testhash.Finalize(calculated);
    BOOST_CHECK(calculated == spec);
}


static void TestKHeavyHash(const std::string &seedin, const std::string &timestamp, const std::string &nonce, const std::string &hexout) {
    uint256 seed = swap256S(seedin.c_str());
    uint256 solution = swap256S(hexout.c_str());
    char *end;
    uint64_t tsb2 = strtoul(timestamp.c_str(), &end, 16);
    uint64_t nb2 = strtoul(nonce.c_str(), &end, 16);
    Span<const unsigned char> ts2(reinterpret_cast<const unsigned char*>(&tsb2), sizeof(uint64_t));
    Span<const unsigned char> n2(reinterpret_cast<const unsigned char*>(&nb2), sizeof(uint64_t));

    KHeavyHash testhash = KHeavyHash(seed);
    testhash.Write(seed).Write(ts2).Write(uint256().ZERO).Write(n2);
    uint256 calculated;
    testhash.Finalize(calculated);

    BOOST_CHECK(calculated == solution);
}


BOOST_AUTO_TEST_CASE(kheavyhash_testvectors) {
    TestKHeavyHash("39b75db95d1d2ae1713a4ad0cf78075990d76b44a3bd73732adf962a8eb7c986",
                   "000001957017f254",
                   "5f0000da6bda07c1",
                   "e61e77ca49277f68c5173912d59a9269b27300aba765714f0200000000000000");

    TestKHeavyHash("4adb5673e68379d083378360584317c8d0f32fb9e4690e9c529f4c4b12cc7466",
                   "00000195704cffd8",
                   "2c2d103a0ead6c8c",
                   "156b13ff345906602e2ffca8f4c8467945fce5acf09ff16a0200000000000000");

    TestKHeavyHash("e0eb18efed0ea7234ed7172f515bebb14c951edc3481e803788c04f630dde14a",
                   "00000195709a5770",
                   "9fe0b4bd5eda06f6",
                   "2d55579419e78e5dbaa35b18c639f558d5759fa21f2dddd90700000000000000");

    TestKHeavyHash("79a3453c258e16e152007852e3dcd4e5ddc9348d6f86fda7b0f74e2735bd2e27",
                   "00000195713662b4",
                   "cc004e99c50c6cb7",
                   "425494d7d794d98ffae3ad864c005e92ae1a13049b192fcc0400000000000000");

    TestKHeavyHash("fb17107f6bb055992c795b67164c9a9967d1af20f7fe8bb93daacd6576a4af2e",
                   "00000195714c9c02",
                   "4d00093784726695",
                   "382351e166120a908a50fcc95fda0c36350991f39ba590a00000000000000000");

    TestKHeavyHash("487abfb9de149f0364014240084a33efcb78aebf40b8fe0ffb2e431188e8c1c3",
                   "000001957170e701",
                   "744911e831357c05",
                   "7c779957b1a673cb8b499cd1e5d61784c7accbecec8c29f80300000000000000");

    TestKHeavyHash("87c4517fbd112611c00aa057bfa505c576da361c71eef3e070d35ac4eac2ce8a",
                   "0000019571c0f690",
                   "d000063959c08ff8",
                   "5fda243396863e0b204e221d53afe035478485326d788f990400000000000000");

    TestKHeavyHash("a49c662199a3c26f1d4fbd9b67efdfe6f4dba63408d3cb322cf99a4670a51ede",
                   "0000019571f30804",
                   "f0000271032d8f63",
                   "581bdfbdb86f5d3bb99354c41acfa0643a83bf7c7377a0910200000000000000");

    TestKHeavyHash("517cb2bd2da4af4941e74ad926069ee5c224bec6860015fc79dae3f4052e9976",
                   "00000195721f2372",
                   "6ec005c84a5c2dc6",
                   "181a97ca4b4f74cf9da3fdd8b20f1b47fcb7c419c35004160000000000000000");

    TestKHeavyHash("833c424f0c0997c02668f2fbe9f45ca35340a845f5940c01d8fe06938fb07d90",
                   "00000195726c40a8",
                   "cc00540841fa904a",
                   "5154717aa9356f550cb575067313926e72a61fec0151577b0700000000000000");

    TestKHeavyHash("ffc89ab98caa15cca8d461358172cb515ce842c6e561a0e37afd42eae1090b2a",
                   "00000195726d68ee",
                   "948010720bcc7d10",
                   "c4aef86cad6d2ebcb8f274232ac901b51b2e34deb6957ac50300000000000000");

    TestKHeavyHash("2e34a4b3ab239c93a61f29a0e1934e44e3311056dfcbbcbd65d83657e8fd6042",
                   "000001957332a6dd",
                   "2a2000c903eaeb86",
                   "774361f7f99199c3e1a2290ffbaae0cc6fae5ffcd0bdf69c0000000000000000");  
}

BOOST_AUTO_TEST_SUITE_END()
