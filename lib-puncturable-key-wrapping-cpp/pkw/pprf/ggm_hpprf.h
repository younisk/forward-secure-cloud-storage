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

#ifndef PUNCTURABLE_KEY_WRAPPING_CPP_GGM_HPPRF_H
#define PUNCTURABLE_KEY_WRAPPING_CPP_GGM_HPPRF_H

#include "../secure_byte_buffer.h"
#include "ggm_pprf_key.h"
#include <bitset>
#include <string>
#include <utility>
#include <vector>

using Tag = std::vector<bool>;
using byte = unsigned char;

/**
 * Implements a hierarchically Puncturable Pseudo-Random Function (HPPRF) using the Goldreich, Goldwasser & Micali (GGM) construction.
 *
 * <div class="csl-entry">Goldreich, O., Goldwasser, S., &#38; Micali, S. (1986). How to construct random functions. <i>Journal of the ACM (JACM)</i>, <i>33</i>(4), 792–807. https://doi.org/10.1145/6490.6503</div>
* <br>
 */
class GGM_HPPRF {
    public:
        /**
         * Punctures the HPPRF on tag. If tag was already punctured on, no exception is thrown.
         * @param tag the tag on which the HPPRF is to be punctured
         * @throws IllegalTagException if the size of the tag exceeds the key's tag length..
         */
        void punc(const Tag &tag);

        /**
         * Evaluates the HPPRF on input tag and returns the result of the evaluation.
         * @param tag the tag
         * @return a SecureByteBuffer
         * @throws IllegalTagException if the HPPRF was punctured on tag or the size of the tag exceeds the key's tag length.
         */
        SecureByteBuffer eval(Tag tag);

        /**
         * Constructs a HPPRF instance using the key.
         * @param key the key
         */
        explicit GGM_HPPRF(PPRFKey key);

        /**
         * Getter for number of punctures performed on the HPPRF.
         * @return number of punctures
         */
        int getNumPuncs();

        /**
         * Getter the tag length of HPPRF
         * @return tag length
         */
        int tagLen();

        /**
         * Serializes the key.
         * @return a secureByteBuffer holding the serialized key.
         */
        SecureByteBuffer serializeKey();

    private:
        PPRFKey key;

        std::string findMatchingPrefix(const Tag &tag);

        SecureByteBuffer
        evalAndGetCoPath(const Tag &tag, const SecretRoot &node, std::vector<SecretRoot> &coPath) const;

        static std::string tag_to_string(const Tag &tag);
};


#endif//PUNCTURABLE_KEY_WRAPPING_CPP_GGM_HPPRF_H