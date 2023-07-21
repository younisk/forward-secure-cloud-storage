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

#ifndef PUNCTURABLE_KEY_WRAPPING_CPP_GGM_PPRF_KEY_H
#define PUNCTURABLE_KEY_WRAPPING_CPP_GGM_PPRF_KEY_H

#include "secret_root.h"
#include <unordered_map>
/*
 * This class maintains an ordering on the nodes. The vector containing the nodes should always be ordered lexicographically.
 */
class PPRFKey {
    public:
        /**
         * Creates a fresh instance of a PPRFKey.
         * @param keyLen the size of the key space in number of bits
         * @param tagLen the size of the tag space in number of bits
         */
        PPRFKey(int keyLen, int tagLen);

        /**
         * Constructs a PPRFKey from a serialized byte string
         * @param serialized the serialized key
         * @return the deserialized key
         */
        static PPRFKey fromSerialized(SecureByteBuffer &serialized);

        /**
         * Creates an instance of a PPRFKey based on the given parameters.
         * @param keyLen the size of the key space in number of bits
         * @param tagLen the size of the tag space in number of bits
         * @param puncs the number of punctures already performed
         * @param nodes a vector of SecretRoots, defining their respective subtrees
         */
        PPRFKey(int keyLen, int tagLen, int puncs, std::unordered_map<std::string, SecretRoot> nodes);
        /**
         * A default constructor, creating an empty key. Used for deserialization.
         */
        PPRFKey();
        /**
         * the size of the key space in number of bits
         */
        int keyLen;
        /**
         * the size of the tag space in number of bits
         */
        int tagLen;
        /**
         * the number of punctures performed on the PPRF using this key
         */
        int puncs;

        std::unordered_map<std::string, SecretRoot> nodes;

        /**
         * Serializes the key for export
         * @return the serialized key
         */
        SecureByteBuffer serialize();
};
#endif//PUNCTURABLE_KEY_WRAPPING_CPP_GGM_PPRF_KEY_H