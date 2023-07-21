#include "pkw/pkw/exceptions.h"
#include "pkw/pkw/naive_pkw.h"
#include <gtest/gtest.h>
#include <iostream>
#include <vector>


class NaivePKWTest : public ::testing::Test {

    protected:
    public:
        NaivePKWTest() : naive(NaivePKW(10)) {
        }

        NaivePKW naive;
};

TEST_F(NaivePKWTest, TestWrapThenUnwrap) {
    std::string key_str = "mykey";
    std::vector<unsigned char> key(key_str.begin(), key_str.end());
    std::string header = "headerinfo";
    std::vector<unsigned char> head(header.begin(), header.end());
    std::vector<unsigned char> wrapped = naive.wrap(1, head, key);
    std::vector<unsigned char> unwrapped = naive.unwrap(1, head, wrapped);
    ASSERT_EQ(unwrapped, key);
}


TEST_F(NaivePKWTest, TestPuncThenWrap) {
    std::string key_str = "mykey";
    std::vector<unsigned char> key(key_str.begin(), key_str.end());
    std::string header = "headerinfo";
    std::vector<unsigned char> head(header.begin(), header.end());
    naive.punc(1);
    ASSERT_THROW(naive.wrap(1, head, key), IllegalTagException);
}

TEST_F(NaivePKWTest, TestWrapPuncThenUnwrap) {
    std::string key_str = "mykey";
    std::vector<unsigned char> key(key_str.begin(), key_str.end());
    std::string header = "headerinfo";
    std::vector<unsigned char> head(header.begin(), header.end());
    std::vector<unsigned char> wrapped = naive.wrap(1, head, key);
    naive.punc(1);
    ASSERT_THROW(naive.unwrap(1, head, wrapped), IllegalTagException);
}

TEST_F(NaivePKWTest, TestNumberPunctures) {
    ASSERT_EQ(naive.getNumPuncs(), 0);
    for (long i = 0; i < 1024; ++i) {
        naive.punc(i);
        ASSERT_EQ(naive.getNumPuncs(), i + 1);
    }
    ASSERT_THROW(naive.punc(1024), IllegalTagException);
}

TEST_F(NaivePKWTest, TestNumberPuncturesReinitialize) {
    ASSERT_EQ(naive.getNumPuncs(), 0);
    naive.punc(12);
    ASSERT_EQ(naive.getNumPuncs(), 1);
    naive.punc(1022);
    ASSERT_EQ(naive.getNumPuncs(), 2);
    auto key = naive.serializeKey();
    auto naive2 = NaivePKWFactory().fromSerialized(key);
    ASSERT_EQ(naive2->getNumPuncs(), 2);
}

TEST_F(NaivePKWTest, TestExportImportKey) {
    auto empty = std::vector<unsigned char>();
    naive.punc(12);
    auto key = naive.serializeKey();
    auto naive2 = NaivePKWFactory().fromSerialized(key);
    ASSERT_NO_THROW(naive2->wrap(0, empty, empty)) << "Wrapping functionality maintained";
    ASSERT_THROW(naive2->wrap(12, empty, empty), IllegalTagException) << "Should throw exception";
}

TEST_F(NaivePKWTest, TestWrapExportImportKeyUnwrap) {
    std::string key_str = "mykey";
    std::vector<unsigned char> dek(key_str.begin(), key_str.end());
    std::string header = "headerinfo";
    std::vector<unsigned char> head(header.begin(), header.end());
    std::vector<unsigned char> wrap = naive.wrap(0, head, dek);

    auto exp = naive.serializeKey();
    auto naive2 = NaivePKWFactory().fromSerialized(exp);

    ASSERT_EQ(dek, naive2->unwrap(0, head, wrap)) << "Wrapping functionality maintained";
}

TEST_F(NaivePKWTest, TestExportImportKeyWithPassword) {
    std::vector<unsigned char> empty = std::vector<unsigned char>();
    naive.punc(12);
    auto exp = naive.serializeAndEncryptKey("myPassword");
    auto naive2 = NaivePKWFactory().fromSerializedAndEncrypted(exp, "myPassword");
    ASSERT_NO_THROW(naive2->wrap(0, empty, empty)) << "Wrapping functionality maintained";
    ASSERT_THROW(naive2->wrap(12, empty, empty), IllegalTagException) << "Should throw exception";
}

TEST_F(NaivePKWTest, TestWrapExportImportKeyUnwrapWithPassword) {
    std::string key_str = "mykey";
    std::vector<unsigned char> dek(key_str.begin(), key_str.end());
    std::string header = "headerinfo";
    std::vector<unsigned char> head(header.begin(), header.end());
    std::vector<unsigned char> wrap = naive.wrap(0, head, dek);

    auto exp = naive.serializeAndEncryptKey("myPassword");
    auto naive2 = NaivePKWFactory().fromSerializedAndEncrypted(exp, "myPassword");

    ASSERT_EQ(dek, naive2->unwrap(0, head, wrap)) << "Wrapping functionality maintained";
}

TEST_F(NaivePKWTest, TestWrapExportImportKeyWithWrongPassword) {
    std::string key_str = "mykey";
    std::vector<unsigned char> dek(key_str.begin(), key_str.end());
    std::string header = "headerinfo";
    std::vector<unsigned char> head(header.begin(), header.end());
    std::vector<unsigned char> wrap = naive.wrap(0, head, dek);

    auto exp = naive.serializeAndEncryptKey("myPassword");
    ASSERT_THROW(NaivePKWFactory().fromSerializedAndEncrypted(exp, "wrongPassword"), ImportException)
                                << "Should not be able to import if decrypted with wrong password";
}