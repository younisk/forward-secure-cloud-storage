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

#include <gtest/gtest.h>
#include <pkw/pprf/ggm_pprf.h>
#include "../../util/tag_util.h"

TEST(TagUtil, EncodeBasic) {
    Tag b;
    b.set(0, true);
    ASSERT_EQ(secure_cloud_storage::tag_to_base64(b), std::string(42, 'A') + "B");
}

TEST(TagUtil, EncodeBasic2) {
    Tag b;
    b.set(255, true);
    ASSERT_EQ(secure_cloud_storage::tag_to_base64(b), "I" + std::string(42, 'A'));
}

TEST(TagUtil, DecodeBasic) {
    Tag expected;
    for (int i: {0, 1}) {
        expected.set(i, true);
    }
    ASSERT_EQ(secure_cloud_storage::tag_from_base64(std::string(42, 'A') + "D"), expected);
}

TEST(TagUtil, DecodeBasic2) {
    Tag expected;
    for (int i: {254, 255}) {
        expected.set(i, true);
    }
    ASSERT_EQ(secure_cloud_storage::tag_from_base64("M" + std::string(42, 'A')), expected);
}

TEST(TagUtil, EncodeDecode) {
    Tag b;
    for (int i: {0, 1, 28, 255, 74, 42}) {
        b.set(i, true);
    }
    ASSERT_EQ(secure_cloud_storage::tag_from_base64(secure_cloud_storage::tag_to_base64(b)),
              b);
}