/***********************************************************************************************************************
 * Copyright 2022 Younis Khalil
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *
 **********************************************************************************************************************/

#ifndef PUNCTURABLE_KEY_WRAPPING_CPP_NAIVE_PKW_H
#define PUNCTURABLE_KEY_WRAPPING_CPP_NAIVE_PKW_H

#include "exceptions.h"
#include "pkw.h"
#include <array>
#include <map>

#define MAC_LEN 12
#define NONCE_LEN 16
#define KEY_LEN 16

using Key = std::map<long, std::array<unsigned char, KEY_LEN> *>;

class NaivePKW : public AbstractPKW<long, std::vector<unsigned char>> {
    public:
        explicit NaivePKW(int tagLen);

        std::vector<unsigned char> unwrap(long tag, std::vector<unsigned char> &header, std::vector<unsigned char> &c) override;

        std::vector<unsigned char>
        wrap(long tag, std::vector<unsigned char> &header, std::vector<unsigned char> &key) override;

        void punc(long tag) override;

        long getNumPuncs() override {
            return numPunctures;
        }

        void secureTeardown() override;

        SecureByteBuffer serializeKey() override;

        virtual ~NaivePKW();

        SecureByteBuffer serializeAndEncryptKey(const std::string &password) override;

    protected:
        explicit NaivePKW(SecureByteBuffer serializedKey);

    private:
        friend class NaivePKWFactory;
        long numPunctures{};
        Key keys;

        void checkTag(long tag) const;

        unsigned char *getAndCheckKey(long tag);
};


class NaivePKWFactory : public AbstractPKWFactory<long, std::vector<unsigned char>> {
    public:
        std::shared_ptr<AbstractPKW<long, std::vector<unsigned char>>> fromSerialized(SecureByteBuffer &serialized) override;
};

class NaivePKWSerializer {
    private:
        static int getInt(SecureByteBuffer b, size_t offset);
        static size_t getSize(SecureByteBuffer b, size_t offset);
        template<typename T>
        void writeT(std::vector<unsigned char> &underlyingBuffer, T t);

    public:
        NaivePKWSerializer(Key keys, long puncs);
        Key keys;
        long puncs;
        SecureByteBuffer serialize();
        static long deserializePuncs(SecureByteBuffer &serialized);
        static Key deserializeKey(SecureByteBuffer &serialized, size_t offset);
        void copy(std::vector<unsigned char> &buffer, const unsigned char *toCopy, size_t size) const;
        static long getLong(SecureByteBuffer b, size_t offset);
};
#endif//PUNCTURABLE_KEY_WRAPPING_CPP_NAIVE_PKW_H