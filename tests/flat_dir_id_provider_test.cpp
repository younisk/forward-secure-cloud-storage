// Copyright 2023. Younis Khalil
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
//  documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
//  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
//  persons to whom the Software is furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
//  Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
//  BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
//  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
//  DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <gtest/gtest.h>

#include "../flat_dir_id_provider.h"
#include "../util/tag_util.h"

namespace scs = secure_cloud_storage;

class FlatDirIdProviderTest : public ::testing::Test {
    public:
        scs::FlatDirIdProvider idProvider;

        FlatDirIdProviderTest() : idProvider(16) {}
};


TEST_F(FlatDirIdProviderTest, SimpleTest) {
    auto id1 = idProvider.get_id("foo");
    ASSERT_EQ(id1.getLocalId(), Tag(0));
    ASSERT_EQ(id1.getRemoteId(), scs::tag_to_base64(0));

    auto id2 = idProvider.get_id("bar");
    ASSERT_EQ(id2.getLocalId(), Tag(1));
    ASSERT_EQ(id2.getRemoteId(), scs::tag_to_base64(1));

    auto id3 = idProvider.get_id("foo/bar");
    ASSERT_EQ(id3.getLocalId(), Tag(0));
    ASSERT_EQ(id3.getRemoteId(), scs::tag_to_base64(2));

    auto id4 = idProvider.get_id("foo/foo");
    ASSERT_EQ(id4.getLocalId(), Tag(1));
    ASSERT_EQ(id4.getRemoteId(), scs::tag_to_base64(3));
}

TEST_F(FlatDirIdProviderTest, SimpleRemoveTest) {
    auto id1 = idProvider.get_id("foo/foo");
    auto id2 = idProvider.get_id("bar");
    auto id3 = idProvider.get_id("foo/bar");

    idProvider.remove(id1);
    ASSERT_FALSE(idProvider.exists_id(id1));
    ASSERT_TRUE(idProvider.exists_id(id2));
    ASSERT_TRUE(idProvider.exists_id(id3));

    ASSERT_THROW(idProvider.get_file_path(id1), std::exception);

    idProvider.removeDir("foo");
    ASSERT_THROW(idProvider.get_file_path(id3), std::exception);
}