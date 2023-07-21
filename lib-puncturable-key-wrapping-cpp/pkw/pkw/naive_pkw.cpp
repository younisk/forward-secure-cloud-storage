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

#include "naive_pkw.h"
#include "../secure_memzero.h"
#include "exceptions.h"
#include "helpers/password_encrypt.h"
#include <cmath>
#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <utility>

using byte = unsigned char;
using std::array;
using std::pair;
using std::vector;

NaivePKW::NaivePKW(SecureByteBuffer serializedKey) {
    this->numPunctures = NaivePKWSerializer::deserializePuncs(serializedKey);
    this->keys = NaivePKWSerializer::deserializeKey(serializedKey, sizeof(long));
}

NaivePKW::NaivePKW(int tagLen) : numPunctures(0) {
    for (long i = 0; i < powl(2, tagLen); ++i) {
        this->keys[i] = new array<byte, KEY_LEN>;
        CryptoPP::OS_GenerateRandomBlock(true, this->keys[i]->data(), this->keys[i]->size());
    }
}

void NaivePKW::punc(long tag) {
    checkTag(tag);
    if (this->keys[tag] == nullptr) {
        return;
    }
    secure_memzero(this->keys[tag]->data(), KEY_LEN);
    delete this->keys[tag];
    this->keys[tag] = nullptr;
    this->numPunctures += 1;
}

vector<byte>
NaivePKW::wrap(long tag, vector<byte> &header, vector<byte> &key) {
    byte *kek = getAndCheckKey(tag);
    long cipherTextLen = MAC_LEN + key.size();
    SecureByteBuffer iv(KEY_LEN);
    SecureByteBuffer enc_key(KEY_LEN);
    std::copy(kek, kek + KEY_LEN, enc_key.begin());
    vector<byte> keycopy = key;
    SecureByteBuffer key_buffer(keycopy);
    return encrypt(key_buffer, enc_key, iv, vector<byte>());
}

vector<byte>
NaivePKW::unwrap(long tag, vector<byte> &header, vector<byte> &c) {
    byte *kek = getAndCheckKey(tag);
    checkTag(tag);
    SecureByteBuffer ciphertext(c);
    SecureByteBuffer enc_key(KEY_LEN);
    SecureByteBuffer iv(KEY_LEN);
    std::copy(kek, kek + KEY_LEN, enc_key.begin());
    SecureByteBuffer plain = decrypt(ciphertext, enc_key, iv, std::vector<unsigned char>());
    return {plain.begin(), plain.end()};
}

byte *NaivePKW::getAndCheckKey(long tag) {
    checkTag(tag);
    byte *kek = keys[tag]->data();
    if (kek == nullptr) {
        throw IllegalTagException();
    }
    return kek;
}

void NaivePKW::checkTag(long tag) const {
    if (tag >= keys.size()) {
        throw IllegalTagException();
    }
}

void NaivePKW::secureTeardown() {
    for (pair<const long, array<byte, KEY_LEN> *> &p: this->keys) {
        if (p.second != nullptr) {
            secure_memzero(p.second->data(), KEY_LEN);
            delete p.second;
            p.second = nullptr;
        }
    }
}

SecureByteBuffer NaivePKW::serializeKey() {
    return NaivePKWSerializer(this->keys, this->numPunctures).serialize();
}


SecureByteBuffer NaivePKW::serializeAndEncryptKey(const std::string &password) {
    SecureByteBuffer serialized = serializeKey();
    return encryptExport(serialized, password);
}

NaivePKW::~NaivePKW() {
    NaivePKW::secureTeardown();
}

std::shared_ptr<AbstractPKW<long, vector<unsigned char>>> NaivePKWFactory::fromSerialized(SecureByteBuffer &serialized) {
    return std::shared_ptr<AbstractPKW<long, vector<unsigned char>>>(new NaivePKW(serialized));// cannot use std::make_shared; constructor protected
}

template<typename T>
void NaivePKWSerializer::writeT(std::vector<unsigned char> &underlyingBuffer, T t) {
    for (int i = 0; i < sizeof(T); ++i) {
        underlyingBuffer.push_back((t >> (8 * i)) & 0xFF);
    }
}

void NaivePKWSerializer::copy(std::vector<unsigned char> &buffer, const unsigned char *toCopy, size_t size) const {
    for (int i = 0; i < size; ++i) {
        buffer.push_back(toCopy[i] & 0xFF);
    }
}

int NaivePKWSerializer::getInt(SecureByteBuffer b, size_t offset) {
    if (b.size() < offset + sizeof(int)) {
        throw DeserializationError();
    }
    int ret = 0;
    for (int i = 0; i < sizeof(int); i++) {
        ret = ret | (b.data()[offset + i] << (i * 8));
    }
    return ret;
}

long NaivePKWSerializer::getLong(SecureByteBuffer b, size_t offset) {
    if (b.size() < offset + sizeof(size_t)) {
        throw DeserializationError();
    }
    long ret = 0;
    for (int i = 0; i < sizeof(size_t); i++) {
        ret = ret | (b.data()[offset + i] << (i * 8));
    }
    return ret;
}

size_t NaivePKWSerializer::getSize(SecureByteBuffer b, size_t offset) {
    if (b.size() < offset + sizeof(size_t)) {
        throw DeserializationError();
    }
    size_t ret = 0;
    for (int i = 0; i < sizeof(size_t); i++) {
        ret = ret | (b.data()[offset + i] << (i * 8));
    }
    return ret;
}
NaivePKWSerializer::NaivePKWSerializer(Key keys, long puncs) : keys(std::move(keys)), puncs(puncs) {}
SecureByteBuffer NaivePKWSerializer::serialize() {
    vector<unsigned char> buffer;
    writeT(buffer, puncs);
    for (auto &entry: keys) {
        if (entry.second != nullptr) {
            writeT(buffer, entry.first);
            copy(buffer, entry.second->begin(), entry.second->size());
        }
    }
    return SecureByteBuffer(buffer);
}
Key NaivePKWSerializer::deserializeKey(SecureByteBuffer &serialized, size_t offset) {
    Key key;
    while (offset + sizeof(long) < serialized.size()) {
        long index = getLong(serialized, offset);
        offset += sizeof(long);
        key[index] = new std::array<unsigned char, KEY_LEN>;
        std::copy(serialized.begin() + offset, serialized.begin() + offset + KEY_LEN, key[index]->begin());
        offset += KEY_LEN;
    }
    return key;
}
long NaivePKWSerializer::deserializePuncs(SecureByteBuffer &serialized) {
    return getLong(serialized, 0);
}