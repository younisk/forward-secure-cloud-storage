// Copyright 2023 Younis Khalil
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
// BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
//

#include "tag_util.h"
#include <iterator>
#include <algorithm>

namespace secure_cloud_storage {

    const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";

    std::string tag_to_base64(const Tag &t) {
        Tag current = t;
        std::string s;
        const Tag mask("111111");
        for (int i = 0; i <= MAX_TAG_LEN / 6; ++i) {
            s.push_back(alphabet[(current & mask).to_ulong()]);
            current >>= 6;
        }
        std::reverse(s.begin(), s.end());
        return s;
    }

    Tag tag_from_base64(const std::string &s) {
        Tag recovered;
        for (auto c: s) {
            recovered <<= 6;
            size_t index = alphabet.find(c, 0);
            Tag part(index);
            recovered |= part;
        }
        return recovered;
    }

} // secure_cloud_storage