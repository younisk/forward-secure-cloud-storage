#include <gtest/gtest.h>

#include <gmock/gmock-matchers.h>
#include <pkw/pprf/ggm_pprf.h>
#include <pkw/pprf/pprf_exceptions.h>
#include <pkw/pprf/pprf_key_serializer.h>
#include <pkw/pprf/secret_root.h>

static const int TEST_KEY_LEN = 128;

class GGMPPRFTest : public ::testing::Test {

    protected:
    public:
        explicit GGMPPRFTest() : pprf(std::move(GGM_PPRF(PPRFKey(TEST_KEY_LEN, 10)))) {}

        GGM_PPRF pprf;

        friend class GGM_PPRF;
};


TEST(Construction, EvalTestFromTwoNodes) {
    SecretRoot n1 = SecretRoot("0101", SecureByteBuffer(TEST_KEY_LEN / 8));
    SecretRoot n2 = SecretRoot("001", SecureByteBuffer(TEST_KEY_LEN / 8));
    GGM_PPRF pprf(PPRFKey(TEST_KEY_LEN, 10, 0, {{n1.getPrefix(), n1},
                                                {n2.getPrefix(), n2}}));
    /* Should choose node n1 as (356)_10 == (0101100100)_2 */
    ASSERT_NO_THROW(pprf.eval(356));

    /* Value found by manual inspection: hkdf_derivation.py */
    unsigned char exp[] = "\xd4\x36\xae\x44\xce\x57\xf9\x72\xa5\xb1\x0b\x70\x2e\x80\x23\x89";

    SecureByteBuffer exp_vect(16);
    std::copy(exp, exp + 16, exp_vect.data());
    ASSERT_THAT(pprf.eval(356), ::testing::Eq(exp_vect));
}

TEST_F(GGMPPRFTest, TestEvalLessMin) {
    ASSERT_THROW(pprf.eval(-1), TagException);
}

TEST_F(GGMPPRFTest, TestEvalMin) {
    ASSERT_NO_THROW(pprf.eval(0));
}

TEST_F(GGMPPRFTest, TestEvalMax) {
    ASSERT_NO_THROW(pprf.eval((1 << 10) - 1));
}

TEST_F(GGMPPRFTest, TestEvalGreaterMax) {
    ASSERT_THROW(pprf.eval(1024), TagException);
}

TEST_F(GGMPPRFTest, TestEvalMuchGreaterMax) {
    ASSERT_THROW(pprf.eval(std::bitset<MAX_TAG_LEN>(1) << 255), TagException);
}


TEST_F(GGMPPRFTest, TestMultiEval) {
    for (int i = 0; i < 200; ++i) {
        ASSERT_NO_THROW(pprf.eval(i));
    }
}

TEST_F(GGMPPRFTest, TestPuncThenEval) {
    ASSERT_NO_THROW(pprf.eval(10));
    pprf.punc(10);
    ASSERT_THROW(pprf.eval(10), TagException);
}

TEST_F(GGMPPRFTest, TestPuncThenEvalOther) {
    GGM_PPRF pprf2(PPRFKey(TEST_KEY_LEN, 10));
    ASSERT_NO_THROW(pprf2.eval(10));
    pprf2.punc(10);
    for (int i = 0; i < 100; ++i) {
        if (i != 10) {
            ASSERT_NO_THROW(pprf2.eval(i));
        }
    }
}

TEST_F(GGMPPRFTest, TestMultiPuncThenEvalOther) {
    GGM_PPRF pprf2(PPRFKey(TEST_KEY_LEN, 10));
    ASSERT_NO_THROW(pprf2.eval(10));
    std::vector<int> toPunc({10, 8, 4, 98});
    for (int p: toPunc) {
        ASSERT_NO_THROW(pprf2.punc(p));
    }
    for (int i = 0; i < 100; ++i) {
        if (std::count(toPunc.begin(), toPunc.end(), i) == 0) {
            ASSERT_NO_THROW(pprf2.eval(i)) << "Could not eval for " << i;
        } else {
            ASSERT_THROW(pprf2.eval(i), TagException) << i << " was punctured";
        }
    }
}

TEST_F(GGMPPRFTest, TestPuncSameValue) {
    ASSERT_NO_THROW(pprf.punc(10));
    ASSERT_NO_THROW(pprf.punc(10));
    ASSERT_THROW(pprf.eval(10), TagException);
}


TEST_F(GGMPPRFTest, TestTagTooLarge) {
    ASSERT_THROW(pprf.eval(2 << 12), TagException);
}

TEST_F(GGMPPRFTest, TestLargeTagSize) {
    auto start_time = std::chrono::high_resolution_clock::now();
    GGM_PPRF pprf2(PPRFKey(TEST_KEY_LEN, 256));
    auto toPunc = {0, 1, 2, 3, 4, 5, 1000};
    for (int i: toPunc) {
        ASSERT_NO_THROW(pprf2.punc(i)) << "tag " << i;
    }
    SecureByteBuffer prev, curr;
    for (int i = 0; i < 2 << 15; ++i) {
        if (std::count(toPunc.begin(), toPunc.end(), i) == 0) {
            ASSERT_NO_THROW(curr = pprf2.eval(i)) << "Could not eval for " << i;
            ASSERT_NE(curr, prev) << "Values should differ";// sanity check
            prev = curr;
        } else {
            ASSERT_THROW(pprf2.eval(i), TagException) << i << " was punctured";
        }
    }
    auto end_time = std::chrono::high_resolution_clock::now();
    std::cout << "Execution took " << (end_time - start_time).count() / pow(10, 6) << "ms." << std::endl;// TODO remove
}

TEST(Serialization, TestSerializeDeserialize) {
    unsigned char keyval[] = "\xd4\x36\xae\x44\xce\x57\xf9\x72";
    SecureByteBuffer keyvalbuff(8);
    std::copy(std::begin(keyval), std::end(keyval), keyvalbuff.data());
    GGM_PPRF pprf1(PPRFKey(64, 64, 28, {{"0",   SecretRoot("0", SecureByteBuffer(8))},
                                        {"100", SecretRoot("100", keyvalbuff)}}));
    SecureByteBuffer serialized = pprf1.serializeKey();
    auto pprf2 = PPRFKeySerializer::deserialize(serialized);
    ASSERT_EQ(pprf2.keyLen, 64);
    ASSERT_EQ(pprf2.tagLen, 64);
    ASSERT_EQ(pprf2.puncs, 28);
    ASSERT_EQ(pprf2.nodes.size(), 2) << "Should have two nodes";
    ASSERT_EQ(pprf2.nodes["0"].getValue(), SecureByteBuffer(8))
                                << "Nodes should be deserialized in same order with same values";
    ASSERT_EQ(pprf2.nodes["100"].getValue(), keyvalbuff)
                                << "Nodes should be deserialized in same order with same values";
}

TEST(BadInitialization, TestZeroTagLength) {
    ASSERT_THROW(GGM_PPRF(PPRFKey(TEST_KEY_LEN, 0)), InitializationException);
}