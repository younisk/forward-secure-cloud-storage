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

#include "ggm_pprf_key.h"
#include "pprf_exceptions.h"
#include "pprf_key_serializer.h"
#include <algorithm>
#include <cryptopp/osrng.h>


PPRFKey::PPRFKey(int keyLen, int tagLen, int puncs, std::unordered_map<std::string, SecretRoot> nodes) : keyLen(keyLen),
                                                                                                         tagLen(tagLen),
                                                                                                         puncs(puncs),
                                                                                                         nodes(std::move(
                                                                                                                 nodes)) {
}

PPRFKey::PPRFKey() {}

SecureByteBuffer PPRFKey::serialize() {
    return PPRFKeySerializer(*this).serialize();
}

PPRFKey PPRFKey::fromSerialized(SecureByteBuffer &serialized) {
    return PPRFKeySerializer::deserialize(serialized);
}

PPRFKey::PPRFKey(int keyLen, int tagLen) : keyLen(keyLen), tagLen(tagLen), puncs(0) {
    if (!(keyLen > 0 && tagLen > 0)) {
        throw InitializationException();
    }
    SecureByteBuffer s(keyLen / 8);
    CryptoPP::OS_GenerateRandomBlock(true, s.data(), s.size());
    nodes.insert({{""},
                  {"", s}});
}