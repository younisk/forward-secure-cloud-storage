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

#ifndef PUNCTURABLE_KEY_WRAPPING_CPP_PPRF_KEY_SERIALIZER_H
#define PUNCTURABLE_KEY_WRAPPING_CPP_PPRF_KEY_SERIALIZER_H


#include "../secure_byte_buffer.h"
#include "ggm_pprf_key.h"
#include "secret_root.h"
class PPRFKeySerializer {
    public:
        explicit PPRFKeySerializer(PPRFKey keyToSerialize) : keyToSerialize(std::move(keyToSerialize)) {}
        SecureByteBuffer serialize();
        static PPRFKey deserialize(SecureByteBuffer &serialized);

    private:
        PPRFKey keyToSerialize;
        static int getInt(SecureByteBuffer b, size_t offset);
        static size_t getSize(SecureByteBuffer buffer, size_t offset);
        static std::string getString(SecureByteBuffer buffer, size_t offset, size_t length);
        static SecureByteBuffer copyValue(SecureByteBuffer from, size_t offset, size_t length);
        static void writeInteger(std::vector<unsigned char> &underlyingBuffer, uint64_t key);
        void writeNode(std::vector<unsigned char> &buffer, const SecretRoot &node);
        static void copy(std::vector<unsigned char> &buffer, const unsigned char *toCopy, size_t size);
        static size_t getUInt64(SecureByteBuffer &b, size_t offset);
};


#endif//PUNCTURABLE_KEY_WRAPPING_CPP_PPRF_KEY_SERIALIZER_H