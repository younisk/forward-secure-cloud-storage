#include "pkw/pkw/hpprf_aead_pkw.h"
#include "pkw/pkw/exceptions.h"
#include <gtest/gtest.h>
#include <iostream>
#include <vector>
#include <bitset>

const int TEST_TAG_LEN = 128;

// creates bool vectors of length 128 encoding the passed int
static std::vector<bool> int2vec(int i) {
    std::bitset<TEST_TAG_LEN> v(i);
    std::vector<bool> ret(v.size());
    for (int j = 0; j < v.size(); ++j) {
        ret[j] = v[j];
    }
    return ret;
}

class HPPRF_AEAD_PKWTest : public ::testing::Test {

    protected:
    public:
        HPPRF_AEAD_PKWTest() : pkw(128) {
        }

        HPPRF_AEAD_PKW pkw;
};

TEST_F(HPPRF_AEAD_PKWTest, TestWrapThenUnwrap) {
    std::string key_str = "mykey";
    std::vector<unsigned char> key(key_str.begin(), key_str.end());
    std::string header = "headerinfo";
    std::vector<unsigned char> head(header.begin(), header.end());
    std::vector<unsigned char> wrapped = pkw.wrap(int2vec(1), head, key);
    std::vector<unsigned char> unwrapped = pkw.unwrap(int2vec(1), head, wrapped);
    ASSERT_EQ(unwrapped, key);
}


TEST_F(HPPRF_AEAD_PKWTest, TestPuncThenWrap) {
    std::string key_str = "mykey";
    std::vector<unsigned char> key(key_str.begin(), key_str.end());
    std::string header = "headerinfo";
    std::vector<unsigned char> head(header.begin(), header.end());
    pkw.punc(int2vec(1));
    ASSERT_THROW(pkw.wrap(int2vec(1), head, key), IllegalTagException);
}

TEST_F(HPPRF_AEAD_PKWTest, TestWrapPuncThenUnwrap) {
    std::string key_str = "mykey";
    std::vector<unsigned char> key(key_str.begin(), key_str.end());
    std::string header = "headerinfo";
    std::vector<unsigned char> head(header.begin(), header.end());
    std::vector<unsigned char> wrapped = pkw.wrap(int2vec(1), head, key);
    pkw.punc(int2vec(1));
    ASSERT_THROW(pkw.unwrap(int2vec(1), head, wrapped), IllegalTagException);
}

TEST_F(HPPRF_AEAD_PKWTest, TestNumberPunctures) {
    ASSERT_EQ(pkw.getNumPuncs(), 0);
    for (int i = 0; i < 1024; ++i) {
        pkw.punc(int2vec(i));
        ASSERT_EQ(pkw.getNumPuncs(), i + 1);
    }
}

TEST_F(HPPRF_AEAD_PKWTest, TestNumberPuncturesReinitialize) {
    ASSERT_EQ(pkw.getNumPuncs(), 0);
    pkw.punc(int2vec(12));
    ASSERT_EQ(pkw.getNumPuncs(), 1);
    pkw.punc(int2vec(1022));
    ASSERT_EQ(pkw.getNumPuncs(), 2);
    auto key = pkw.serializeKey();
    std::cout << "Size of serialized key: " << key.size() << " Bytes" << std::endl;// TODO remove
    auto pkw2 = HPPRF_AEAD_PKW_Factory().fromSerialized(key);
    ASSERT_EQ(pkw2->getNumPuncs(), 2);
}

TEST_F(HPPRF_AEAD_PKWTest, TestExportImportKey) {
    std::vector<unsigned char> empty = std::vector<unsigned char>();
    pkw.punc(int2vec(12));
    auto key = pkw.serializeKey();
    auto pkw2 = HPPRF_AEAD_PKW_Factory().fromSerialized(key);
    ASSERT_NO_THROW(pkw2->wrap(int2vec(0), empty, empty)) << "Wrapping functionality maintained";
    ASSERT_THROW(pkw2->wrap(int2vec(12), empty, empty), IllegalTagException) << "Should throw exception";
}

TEST_F(HPPRF_AEAD_PKWTest, TestWrapExportImportKeyUnwrap) {
    std::string key_str = "mykey";
    std::vector<unsigned char> dek(key_str.begin(), key_str.end());
    std::string header = "headerinfo";
    std::vector<unsigned char> head(header.begin(), header.end());
    std::vector<unsigned char> wrap = pkw.wrap(int2vec(0), head, dek);

    auto exp = pkw.serializeKey();
    auto pkw2 = HPPRF_AEAD_PKW_Factory().fromSerialized(exp);

    ASSERT_EQ(dek, pkw2->unwrap(int2vec(0), head, wrap)) << "Wrapping functionality maintained";
}

TEST_F(HPPRF_AEAD_PKWTest, TestExportImportKeyWithPassword) {
    std::vector<unsigned char> empty = std::vector<unsigned char>();
    pkw.punc(int2vec(12));
    auto exp = pkw.serializeAndEncryptKey("myPassword");
    auto pkw2 = HPPRF_AEAD_PKW_Factory().fromSerializedAndEncrypted(exp, "myPassword");
    ASSERT_NO_THROW(pkw2->wrap(int2vec(0), empty, empty)) << "Wrapping functionality maintained";
    ASSERT_THROW(pkw2->wrap(int2vec(12), empty, empty), IllegalTagException) << "Should throw exception";
}

TEST_F(HPPRF_AEAD_PKWTest, TestWrapExportImportKeyUnwrapWithPassword) {
    std::string key_str = "mykey";
    std::vector<unsigned char> dek(key_str.begin(), key_str.end());
    std::string header = "headerinfo";
    std::vector<unsigned char> head(header.begin(), header.end());
    std::vector<unsigned char> wrap = pkw.wrap(int2vec(0), head, dek);

    auto exp = pkw.serializeAndEncryptKey("myPassword");
    auto pkw2 = HPPRF_AEAD_PKW_Factory().fromSerializedAndEncrypted(exp, "myPassword");

    ASSERT_EQ(dek, pkw2->unwrap(int2vec(0), head, wrap)) << "Wrapping functionality maintained";
}

TEST_F(HPPRF_AEAD_PKWTest, TestWrapExportImportKeyWithWrongPassword) {
    std::string key_str = "mykey";
    std::vector<unsigned char> dek(key_str.begin(), key_str.end());
    std::string header = "headerinfo";
    std::vector<unsigned char> head(header.begin(), header.end());
    std::vector<unsigned char> wrap = pkw.wrap(int2vec(0), head, dek);

    auto exp = pkw.serializeAndEncryptKey("myPassword");
    ASSERT_THROW(HPPRF_AEAD_PKW_Factory().fromSerializedAndEncrypted(exp, "wrongPassword"), ImportException)
                                << "Should not be able to import if decrypted with wrong password";
}