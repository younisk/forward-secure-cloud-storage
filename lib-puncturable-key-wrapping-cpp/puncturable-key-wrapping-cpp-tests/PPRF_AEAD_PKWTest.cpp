#include "pkw/pkw/pprf_aead_pkw.h"
#include "pkw/pkw/exceptions.h"
#include <gtest/gtest.h>
#include <iostream>
#include <vector>


class PPRF_AEAD_PKWTest : public ::testing::Test {

    protected:
    public:
        PPRF_AEAD_PKWTest() : pkw(128, 128) {
        }

        PPRF_AEAD_PKW pkw;
};

TEST_F(PPRF_AEAD_PKWTest, TestWrapThenUnwrap) {
    std::string key_str = "mykey";
    std::vector<unsigned char> key(key_str.begin(), key_str.end());
    std::string header = "headerinfo";
    std::vector<unsigned char> head(header.begin(), header.end());
    std::vector<unsigned char> wrapped = pkw.wrap(1, head, key);
    std::vector<unsigned char> unwrapped = pkw.unwrap(1, head, wrapped);
    ASSERT_EQ(unwrapped, key);
}


TEST_F(PPRF_AEAD_PKWTest, TestPuncThenWrap) {
    std::string key_str = "mykey";
    std::vector<unsigned char> key(key_str.begin(), key_str.end());
    std::string header = "headerinfo";
    std::vector<unsigned char> head(header.begin(), header.end());
    pkw.punc(1);
    ASSERT_THROW(pkw.wrap(1, head, key), IllegalTagException);
}

TEST_F(PPRF_AEAD_PKWTest, TestWrapPuncThenUnwrap) {
    std::string key_str = "mykey";
    std::vector<unsigned char> key(key_str.begin(), key_str.end());
    std::string header = "headerinfo";
    std::vector<unsigned char> head(header.begin(), header.end());
    std::vector<unsigned char> wrapped = pkw.wrap(1, head, key);
    pkw.punc(1);
    ASSERT_THROW(pkw.unwrap(1, head, wrapped), IllegalTagException);
}

TEST_F(PPRF_AEAD_PKWTest, TestNumberPunctures) {
    ASSERT_EQ(pkw.getNumPuncs(), 0);
    for (long i = 0; i < 1024; ++i) {
        pkw.punc(i);
        ASSERT_EQ(pkw.getNumPuncs(), i + 1);
    }
    Tag t;
    t.set(128, true);
    ASSERT_THROW(pkw.punc(t), IllegalTagException);
}

TEST_F(PPRF_AEAD_PKWTest, TestNumberPuncturesReinitialize) {
    ASSERT_EQ(pkw.getNumPuncs(), 0);
    pkw.punc(12);
    ASSERT_EQ(pkw.getNumPuncs(), 1);
    pkw.punc(1022);
    ASSERT_EQ(pkw.getNumPuncs(), 2);
    auto key = pkw.serializeKey();
    std::cout << "Size of serialized key: " << key.size() << " Bytes" << std::endl;// TODO remove
    auto pkw2 = PPRF_AEAD_PKW_Factory().fromSerialized(key);
    ASSERT_EQ(pkw2->getNumPuncs(), 2);
}

TEST_F(PPRF_AEAD_PKWTest, TestExportImportKey) {
    std::vector<unsigned char> empty = std::vector<unsigned char>();
    pkw.punc(12);
    auto key = pkw.serializeKey();
    auto pkw2 = PPRF_AEAD_PKW_Factory().fromSerialized(key);
    ASSERT_NO_THROW(pkw2->wrap(0, empty, empty)) << "Wrapping functionality maintained";
    ASSERT_THROW(pkw2->wrap(12, empty, empty), IllegalTagException) << "Should throw exception";
}

TEST_F(PPRF_AEAD_PKWTest, TestWrapExportImportKeyUnwrap) {
    std::string key_str = "mykey";
    std::vector<unsigned char> dek(key_str.begin(), key_str.end());
    std::string header = "headerinfo";
    std::vector<unsigned char> head(header.begin(), header.end());
    std::vector<unsigned char> wrap = pkw.wrap(0, head, dek);

    auto exp = pkw.serializeKey();
    auto pkw2 = PPRF_AEAD_PKW_Factory().fromSerialized(exp);

    ASSERT_EQ(dek, pkw2->unwrap(0, head, wrap)) << "Wrapping functionality maintained";
}

TEST_F(PPRF_AEAD_PKWTest, TestExportImportKeyWithPassword) {
    std::vector<unsigned char> empty = std::vector<unsigned char>();
    pkw.punc(12);
    auto exp = pkw.serializeAndEncryptKey("myPassword");
    auto pkw2 = PPRF_AEAD_PKW_Factory().fromSerializedAndEncrypted(exp, "myPassword");
    ASSERT_NO_THROW(pkw2->wrap(0, empty, empty)) << "Wrapping functionality maintained";
    ASSERT_THROW(pkw2->wrap(12, empty, empty), IllegalTagException) << "Should throw exception";
}

TEST_F(PPRF_AEAD_PKWTest, TestWrapExportImportKeyUnwrapWithPassword) {
    std::string key_str = "mykey";
    std::vector<unsigned char> dek(key_str.begin(), key_str.end());
    std::string header = "headerinfo";
    std::vector<unsigned char> head(header.begin(), header.end());
    std::vector<unsigned char> wrap = pkw.wrap(0, head, dek);

    auto exp = pkw.serializeAndEncryptKey("myPassword");
    auto pkw2 = PPRF_AEAD_PKW_Factory().fromSerializedAndEncrypted(exp, "myPassword");

    ASSERT_EQ(dek, pkw2->unwrap(0, head, wrap)) << "Wrapping functionality maintained";
}

TEST_F(PPRF_AEAD_PKWTest, TestWrapExportImportKeyWithWrongPassword) {
    std::string key_str = "mykey";
    std::vector<unsigned char> dek(key_str.begin(), key_str.end());
    std::string header = "headerinfo";
    std::vector<unsigned char> head(header.begin(), header.end());
    std::vector<unsigned char> wrap = pkw.wrap(0, head, dek);

    auto exp = pkw.serializeAndEncryptKey("myPassword");
    ASSERT_THROW(PPRF_AEAD_PKW_Factory().fromSerializedAndEncrypted(exp, "wrongPassword"), ImportException)
                                << "Should not be able to import if decrypted with wrong password";
}