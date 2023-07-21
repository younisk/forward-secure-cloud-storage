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

#ifndef PUNCTURABLE_KEY_WRAPPING_CPP_ABSTRACT_PKW_H
#define PUNCTURABLE_KEY_WRAPPING_CPP_ABSTRACT_PKW_H
#include "../secure_byte_buffer.h"
#include "helpers/password_encrypt.h"
#include <memory>
#include <vector>

/**
 * The interface an implementation of a puncturable must provide
 * @tparam T, the type of the tag
 * @tparam C, the type of the ciphertext
 */
template<class T, class C>
class AbstractPKW {
    public:
        /**
         * A function to wrap a key, using the tag and a header.
         * @param tag the tag
         * @param header the header, additional data that is integrity protected but not encrypted
         * @param key the key to be wrapped
         * @return a ciphertext
         */
        virtual C
        wrap(T tag, std::vector<unsigned char> &header, std::vector<unsigned char> &key) = 0;

        /**
         * A function to unwrap a key that was wrapped using wrap.
         * @param tag the tag with which the key was wrapped
         * @param header he header with which the key was wrapped
         * @param c the ciphertext
         * @return the wrapped key
         */
        virtual std::vector<unsigned char>
        unwrap(T tag, std::vector<unsigned char> &header, C &c) = 0;

        /**
         * Punctures on tag. Subsequent calls to wrap or unwrap with this tag will fail.
         * @param tag the tag
         */
        virtual void punc(T tag) = 0;

        /**
         * Returns the number punctures that have been performed.
         * @return the number of punctures
         */
        virtual long getNumPuncs() = 0;

        /**
         * Securely erases all sensitive material.
         */
        virtual void secureTeardown() = 0;

        /**
         * Serializes the key.
         * @return the serialized key.
         */
        virtual SecureByteBuffer serializeKey() = 0;

        /**
         * Serializes the key and additionally encrypts the serialized key with a password-derived key.
         * @param password the password.
         * @return the serialized and encrypted key.
         */
        virtual SecureByteBuffer serializeAndEncryptKey(const std::string &password) = 0;
};

template<class T, class C>
class AbstractPKWFactory {
    public:
        /**
         * Pure virtual function: construct a shared pointer to an AbstractPKW from a serialized key.
         * @param serialized the serialized key.
         * @return shared pointer to an AbstractPKW
         */
        virtual std::shared_ptr<AbstractPKW<T, C>> fromSerialized(SecureByteBuffer &serialized) = 0;

        /**
         * Construct shared pointer to an instatiation of AbstractPKW from an encrypted serialized key.
         * @param serializedAndEncrypted the serialized key
         * @param password the password used for the encryption
         * @return shared pointer to an AbstractPKW
         */
        std::shared_ptr<AbstractPKW<T, C>> fromSerializedAndEncrypted(SecureByteBuffer &serializedAndEncrypted, const std::string &password) {
            SecureByteBuffer decrypted = decryptExport(serializedAndEncrypted, password);
            return fromSerialized(decrypted);
        }
};
#endif//PUNCTURABLE_KEY_WRAPPING_CPP_ABSTRACT_PKW_H