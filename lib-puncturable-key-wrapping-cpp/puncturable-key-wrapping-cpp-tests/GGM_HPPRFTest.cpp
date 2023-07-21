#include <gtest/gtest.h>

#include <gmock/gmock-matchers.h>
#include <pkw/pprf/ggm_hpprf.h>
#include <pkw/pprf/pprf_exceptions.h>
#include <pkw/pprf/pprf_key_serializer.h>
#include <pkw/pprf/secret_root.h>
#include <bitset>

static const int TEST_KEY_LEN = 128;
static const int TEST_TAG_LEN = 128;


static std::vector<bool> int2vec(int i) {
    std::bitset<TEST_TAG_LEN> v(i);
    std::vector<bool> ret(v.size());
    for (int j = 0; j < v.size(); ++j) {
        ret[j] = v[j];
    }
    return ret;
}

class GGMHPPRFTest : public ::testing::Test {

    protected:
    public:
        explicit GGMHPPRFTest() : pprf(std::move(GGM_HPPRF(PPRFKey(TEST_KEY_LEN, TEST_TAG_LEN)))) {}

        GGM_HPPRF pprf;

        friend class GGM_HPPRF;
};


TEST(ConstructionH, EvalTestFromTwoNodes) {
    SecretRoot n1 = SecretRoot("0101", SecureByteBuffer(TEST_KEY_LEN / 8));
    SecretRoot n2 = SecretRoot("001", SecureByteBuffer(TEST_KEY_LEN / 8));
    GGM_HPPRF pprf(PPRFKey(TEST_KEY_LEN, 10, 0, {{n1.getPrefix(), n1},
                                                 {n2.getPrefix(), n2}}));
    /* Should choose node n1 as (356)_10 == (0101100100)_2 */
    ASSERT_NO_THROW(pprf.eval({0, 1, 0, 1, 1, 0, 0, 1, 0, 0}));

    /* Value found by manual inspection: hkdf_derivation.py */
    unsigned char exp[] = "\xe9\x24\xff\x50\x0b\xa7\xd3\x70\x4f\xfb\x9f\x9b\x7d\xcd\xe8\xee";

    SecureByteBuffer exp_vect(16);
    std::copy(exp, exp + 16, exp_vect.data());
    ASSERT_THAT(pprf.eval({0, 1, 0, 1, 1, 0, 0, 1, 0, 0}), ::testing::Eq(exp_vect));
}

// No disallowed tags anymore!
//TEST_F(GGMHPPRFTest, TestEvalLessMin) {
//    ASSERT_THROW(pprf.eval(), TagException);
//}

TEST_F(GGMHPPRFTest, TestEvalMin) {
    ASSERT_NO_THROW(pprf.eval({}));
}


TEST_F(GGMHPPRFTest, TestMultiEvalIncrSize) {
    for (int i = 1; i < 1000; ++i) {
        ASSERT_NO_THROW(pprf.eval(std::vector<bool>(i)));
    }
}

TEST_F(GGMHPPRFTest, TestPuncThenEval) {
    ASSERT_NO_THROW(pprf.eval(int2vec(10)));
    pprf.punc(int2vec(10));
    ASSERT_THROW(pprf.eval(int2vec(10)), TagException);
}

TEST_F(GGMHPPRFTest, TestPuncThenEvalOther) {
    GGM_HPPRF pprf2(PPRFKey(TEST_KEY_LEN, 10));
    ASSERT_NO_THROW(pprf2.eval(int2vec(10)));
    pprf2.punc(int2vec(10));
    for (int i = 0; i < 100; ++i) {
        if (i != 10) {
            ASSERT_NO_THROW(pprf2.eval(int2vec(i))) << "Eval of value " << i << " causes exception\n";
        }
    }
}

TEST_F(GGMHPPRFTest, TestMultiPuncThenEvalOther) {
    GGM_HPPRF pprf2(PPRFKey(TEST_KEY_LEN, 10));
    ASSERT_NO_THROW(pprf2.eval(int2vec(10)));
    std::vector<std::vector<bool>> toPunc({int2vec(10), int2vec(8), int2vec(4), int2vec(96)});
    for (const auto &p: toPunc) {
        ASSERT_NO_THROW(pprf2.punc(p));
    }
    for (int i = 0; i < 100; ++i) {
        if (std::count(toPunc.begin(), toPunc.end(), int2vec(i)) == 0) {
            ASSERT_NO_THROW(pprf2.eval(int2vec(i))) << "Could not eval for " << i;
        } else {
            ASSERT_THROW(pprf2.eval(int2vec(i)), TagException) << i << " was punctured";
        }
    }
}

TEST_F(GGMHPPRFTest, TestPuncSameValue) {
    ASSERT_NO_THROW(pprf.punc(int2vec(10)));
    ASSERT_NO_THROW(pprf.punc(int2vec(10)));
    ASSERT_THROW(pprf.eval(int2vec(10)), TagException);
}

TEST_F(GGMHPPRFTest, TestHierarchPunc) {
    ASSERT_NO_THROW(pprf.eval({1, 0}));
    ASSERT_NO_THROW(pprf.punc({1}));
    ASSERT_THROW(pprf.eval({1}), TagException);
    ASSERT_THROW(pprf.eval({1, 0}), TagException);
    ASSERT_THROW(pprf.eval({1, 1}), TagException);
    ASSERT_NO_THROW(pprf.eval({0}));
    ASSERT_NO_THROW(pprf.eval({0, 0}));
    ASSERT_NO_THROW(pprf.eval({0, 1}));
}


TEST_F(GGMHPPRFTest, TestLargeTagSize) {
    auto start_time = std::chrono::high_resolution_clock::now();
    GGM_HPPRF pprf2(PPRFKey(TEST_KEY_LEN, 256));
    auto toPunc = {0, 1, 2, 3, 4, 5, 1000};
    for (int i: toPunc) {
        ASSERT_NO_THROW(pprf2.punc(int2vec(i))) << "tag " << i;
    }
    SecureByteBuffer prev, curr;
    for (int i = 0; i < 2 << 15; ++i) {
        if (std::count(toPunc.begin(), toPunc.end(), i) == 0) {
            ASSERT_NO_THROW(curr = pprf2.eval(int2vec(i))) << "Could not eval for " << i;
            ASSERT_NE(curr, prev) << "Values should differ";// sanity check
            prev = curr;
        } else {
            ASSERT_THROW(pprf2.eval(int2vec(i)), TagException) << i << " was punctured";
        }
    }
    auto end_time = std::chrono::high_resolution_clock::now();
    std::cout << "Execution took " << (end_time - start_time).count() / pow(10, 6) << "ms." << std::endl;// TODO remove
}

TEST(SerializationH, TestSerializeDeserialize) {
    unsigned char keyval[] = "\xd4\x36\xae\x44\xce\x57\xf9\x72";
    SecureByteBuffer keyvalbuff(8);
    std::copy(std::begin(keyval), std::end(keyval), keyvalbuff.data());
    GGM_HPPRF pprf1(PPRFKey(64, 64, 28, {{"0",   SecretRoot("0", SecureByteBuffer(8))},
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

TEST(BadInitializationH, TestZeroTagLength) {
    ASSERT_THROW(GGM_HPPRF(PPRFKey(TEST_KEY_LEN, 0)), InitializationException);
}

TEST(ConstructionH, TestPuncFromNonExistant) {
    SecretRoot n0 = SecretRoot("1", SecureByteBuffer(TEST_KEY_LEN / 8));
    SecretRoot n1 = SecretRoot("011", SecureByteBuffer(TEST_KEY_LEN / 8));
    SecretRoot n2 = SecretRoot("001", SecureByteBuffer(TEST_KEY_LEN / 8));
    SecretRoot n3 = SecretRoot("0001", SecureByteBuffer(TEST_KEY_LEN / 8));
    SecretRoot n4 = SecretRoot("00001", SecureByteBuffer(TEST_KEY_LEN / 8));
    GGM_HPPRF pprf(PPRFKey(TEST_KEY_LEN, 10, 0, {{n0.getPrefix(), n0},
                                                 {n1.getPrefix(), n1},
                                                 {n2.getPrefix(), n2},
                                                 {n3.getPrefix(), n3},
                                                 {n4.getPrefix(), n4}}));
    ASSERT_THROW(pprf.eval({0}), TagException); // Should be punctured

    auto size_before = pprf.serializeKey();

    ASSERT_NO_THROW(pprf.punc({0})); // should be able to puncture on a prefix

    ASSERT_LT(pprf.serializeKey().size(), size_before.size());

    ASSERT_THROW(pprf.eval({0, 1, 1}), TagException);
    ASSERT_THROW(pprf.eval({0, 0, 1}), TagException);
    ASSERT_THROW(pprf.eval({0, 0, 0, 1}), TagException);
    ASSERT_THROW(pprf.eval({0, 0, 0, 0, 1}), TagException);

    ASSERT_NO_THROW(pprf.eval({1}));
    ASSERT_NO_THROW(pprf.eval({1, 0}));
}