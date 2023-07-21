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

#ifndef PUNCTURABLE_KEY_WRAPPING_CPP_PPRF_AEAD_PKW_H
#define PUNCTURABLE_KEY_WRAPPING_CPP_PPRF_AEAD_PKW_H


#include "../pprf/ggm_pprf.h"
#include "pkw.h"
#include <vector>

using ciphertext = std::vector<unsigned char>;

/**
 * Puncturable Key Wrapping instantiated using composition of a Puncturable Pseudo-Random Function (PPRF) and an AEAD scheme
 * <br>
 * <div class="csl-entry">Backendal, M., Günther, F., &#38; Paterson, K. G. (2022). Puncturable Key Wrapping and Its Applications. <i>Cryptology EPrint Archive</i>.</div>
 */
class PPRF_AEAD_PKW : public AbstractPKW<Tag, ciphertext> {
    public:
        /**
         * Constructs a fresh instance of the PKW.
         * @param tagLen the size of the tag space in number of bits.
         * @param keyLen the size of the key space in number of bits.
         */
        PPRF_AEAD_PKW(int tagLen, int keyLen);

        /**
         * Reconstructs a previous instance using the serialized key as input
         * @param serializedKey the serialized key
         */
        explicit PPRF_AEAD_PKW(SecureByteBuffer serializedKey);

        ciphertext wrap(Tag tag, std::vector<unsigned char> &header, std::vector<unsigned char> &key) override;
        std::vector<unsigned char> unwrap(Tag tag, std::vector<unsigned char> &header, ciphertext &c) override;
        void punc(Tag tag) override;
        long getNumPuncs() override;
        void secureTeardown() override;
        SecureByteBuffer serializeKey() override;
        SecureByteBuffer serializeAndEncryptKey(const std::string &password) override;

    private:
        GGM_PPRF pprf;
};

class PPRF_AEAD_PKW_Factory : public AbstractPKWFactory<Tag, ciphertext> {
    public:
        std::shared_ptr<AbstractPKW<Tag, ciphertext>> fromSerialized(SecureByteBuffer &serialized) override;
};

#endif//PUNCTURABLE_KEY_WRAPPING_CPP_PPRF_AEAD_PKW_H