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
#include "../hierarch_id_provider.h"

namespace scs = secure_cloud_storage;

class HierarchTestFixture : public ::testing::Test {
    public:
        scs::HierarchIdProvider id_provider;
};

static Tag int2tag(int i) {
    std::bitset<MAX_DIR_SIZE> bs(i);
    Tag t(bs.size());
    for (int j = 0; j < bs.size(); j++) {
        t[j] = bs[bs.size() - 1 - j];
    }
    return t;
}

static Tag ints2tag(const std::vector<int> &is) {
    Tag t;
    t.reserve(is.size() * MAX_DIR_SIZE);
    for (auto i: is) {
        Tag temp = int2tag(i);
        t.insert(t.end(), temp.begin(), temp.end());
    }
    return t;
}

TEST_F(HierarchTestFixture, HelperInts2Tag) {
    Tag t(MAX_DIR_SIZE * 3);
    // expect a tag of all zeros for first tag
    ASSERT_EQ(t, ints2tag({0, 0, 0}));
    t[t.size() - 1] = true;
    ASSERT_EQ(t, ints2tag({0, 0, 1}));
    t[0] = true;
    ASSERT_EQ(t, ints2tag({32768, 0, 1}));

}

TEST_F(HierarchTestFixture, RootHasEmptyTag) {
    Tag t;
    ASSERT_EQ(id_provider.get_id("").getLocalId(), t);
}

TEST_F(HierarchTestFixture, TagAsExpected) {
    Tag t(MAX_DIR_SIZE * 3);
    // expect a tag of all zeros for first tag
    ASSERT_EQ(id_provider.get_id("path/one/file.txt").getLocalId(), t);
}

TEST_F(HierarchTestFixture, TagAsExpectedComplex) {
    // expect a tag of all zeros for first tag
    ASSERT_EQ(id_provider.get_id("path/one/file1.txt").getLocalId(), ints2tag({0, 0, 0}));
    ASSERT_EQ(id_provider.get_id("path/one/file2.txt").getLocalId(), ints2tag({0, 0, 1}));
    ASSERT_EQ(id_provider.get_id("path/one/file3.txt").getLocalId(), ints2tag({0, 0, 2}));

    ASSERT_EQ(id_provider.get_id("path/two/file1.txt").getLocalId(), ints2tag({0, 1, 0}));
    ASSERT_EQ(id_provider.get_id("path/two/file2.txt").getLocalId(), ints2tag({0, 1, 1}));

    ASSERT_EQ(id_provider.get_id("path/one").getLocalId(), ints2tag({0, 0}));
    ASSERT_EQ(id_provider.get_id("path/two").getLocalId(), ints2tag({0, 1}));
}

TEST_F(HierarchTestFixture, TagAsExpectedComplexWithRemove) {
    // expect a tag of all zeros for first tag
    ASSERT_EQ(id_provider.get_id("path/one/file1.txt").getLocalId(), ints2tag({0, 0, 0}));
    ASSERT_EQ(id_provider.get_id("path/one/file2.txt").getLocalId(), ints2tag({0, 0, 1}));
    ASSERT_EQ(id_provider.get_id("path/one/file3.txt").getLocalId(), ints2tag({0, 0, 2}));

    id_provider.remove(id_provider.get_id("path/one"));

    ASSERT_FALSE(id_provider.exists_path("path/one"));
    ASSERT_FALSE(id_provider.exists_path("path/one/file1.txt"));
    ASSERT_FALSE(id_provider.exists_path("path/one/file2.txt"));
    ASSERT_FALSE(id_provider.exists_path("path/one/file3.txt"));

    ASSERT_EQ(id_provider.get_number_dirs(), 1);

    ASSERT_EQ(id_provider.get_id("path/file1.txt").getLocalId(), ints2tag({0, 1}));

    ASSERT_EQ(id_provider.get_number_dirs(), 2);

    ASSERT_EQ(id_provider.get_id("path/two/file1.txt").getLocalId(), ints2tag({0, 2, 0}));
    ASSERT_EQ(id_provider.get_id("path/two/file2.txt").getLocalId(), ints2tag({0, 2, 1}));

    ASSERT_EQ(id_provider.get_number_dirs(), 3);

    id_provider.remove(id_provider.get_id("path"));

    ASSERT_FALSE(id_provider.exists_path("path/two"));
    ASSERT_FALSE(id_provider.exists_path("path/two/file1.txt"));
    ASSERT_FALSE(id_provider.exists_path("path/two/file2.txt"));

    ASSERT_EQ(id_provider.get_number_dirs(), 1);


    ASSERT_EQ(id_provider.get_id("path/one/file1.txt").getLocalId(), ints2tag({1, 0, 0}));
    ASSERT_EQ(id_provider.get_id("path/one/file2.txt").getLocalId(), ints2tag({1, 0, 1}));
    ASSERT_EQ(id_provider.get_id("path/one/file3.txt").getLocalId(), ints2tag({1, 0, 2}));

    ASSERT_EQ(id_provider.get_number_dirs(), 3);
}

TEST_F(HierarchTestFixture, DeleteFilesUntilEmpty) {
    auto id1 = id_provider.get_id("path/one/file1.txt");
    auto id2 = id_provider.get_id("path/one/file2.txt");
    auto id3 = id_provider.get_id("path/one/file3.txt");
    auto id4 = id_provider.get_id("path/two/file1.txt");
    auto id5 = id_provider.get_id("path/two/file2.txt");
    auto id6 = id_provider.get_id("path/two/file3.txt");

    ASSERT_EQ(id_provider.get_number_dirs(), 4);

    id_provider.remove(id1);
    ASSERT_EQ(id_provider.get_number_dirs(), 4);
    id_provider.remove(id2);
    ASSERT_EQ(id_provider.get_number_dirs(), 4);
    id_provider.remove(id3);
    ASSERT_EQ(id_provider.get_number_dirs(), 3);
    id_provider.remove(id4);
    ASSERT_EQ(id_provider.get_number_dirs(), 3);
    id_provider.remove(id5);
    ASSERT_EQ(id_provider.get_number_dirs(), 3);
    id_provider.remove(id6);
    ASSERT_EQ(id_provider.get_number_dirs(), 1);
}

TEST_F(HierarchTestFixture, DeleteRoot) {
    auto id1 = id_provider.get_id("path/one/file1.txt");
    auto id2 = id_provider.get_id("path/one/file2.txt");
    auto id3 = id_provider.get_id("path/one/file3.txt");
    auto id4 = id_provider.get_id("path/two/file1.txt");
    auto id5 = id_provider.get_id("path/two/file2.txt");
    auto id6 = id_provider.get_id("path/two/file3.txt");

    ASSERT_NO_THROW(id_provider.remove(id_provider.get_id("")));
    ASSERT_EQ(id_provider.get_number_dirs(), 0);

    ASSERT_THROW(id_provider.get_id("any"), std::exception);
}

TEST_F(HierarchTestFixture, TestRepeatedGet) {
    auto id1 = id_provider.get_id("path/one/file1.txt");
    auto id2 = id_provider.get_id("path/one/file2.txt");
    auto id3 = id_provider.get_id("path/one/file3.txt");
    auto id4 = id_provider.get_id("path/two/file1.txt");
    auto id5 = id_provider.get_id("path/two/file2.txt");
    auto id6 = id_provider.get_id("path/two/file3.txt");


    ASSERT_EQ(id_provider.get_id("path/one/file1.txt"), id1);
    ASSERT_EQ(id_provider.get_id("path/one/file2.txt"), id2);
    ASSERT_EQ(id_provider.get_id("path/one/file3.txt"), id3);
    ASSERT_EQ(id_provider.get_id("path/two/file1.txt"), id4);
    ASSERT_EQ(id_provider.get_id("path/two/file2.txt"), id5);
    ASSERT_EQ(id_provider.get_id("path/two/file3.txt"), id6);

}

TEST_F(HierarchTestFixture, TestComplexRemoveDirCount) {
    auto id1 = id_provider.get_id("path/one/two/three/four/five/six/file1.txt");
    auto id2 = id_provider.get_id("path/one/file2.txt");
    auto id3 = id_provider.get_id("path/one/two/file3.txt");
    auto id4 = id_provider.get_id("path/two/four/five/file1.txt");
    auto id5 = id_provider.get_id("path/two/file2.txt");
    auto id6 = id_provider.get_id("path/two/file3.txt");

    ASSERT_EQ(id_provider.get_number_dirs(), 11);

    id_provider.remove(id4);

    ASSERT_EQ(id_provider.get_number_dirs(), 9);

    id_provider.remove(id1);

    ASSERT_EQ(id_provider.get_number_dirs(), 5);

}


TEST_F(HierarchTestFixture, TestDirCountRemove) {
    auto id1 = id_provider.get_id("path/one/two/three/four/five/six/file1.txt");
    auto id2 = id_provider.get_id("path/one/file2.txt");
    auto id3 = id_provider.get_id("path/one/two/file3.txt");
    auto id4 = id_provider.get_id("path/two/four/five/file1.txt");
    auto id5 = id_provider.get_id("path/two/file2.txt");
    auto id6 = id_provider.get_id("path/two/file3.txt");

    ASSERT_EQ(id_provider.get_number_dirs(), 11);

    id_provider.remove(id1);
    ASSERT_EQ(id_provider.get_number_dirs(), 7);

    id_provider.get_id("path/one/file3.txt");

    id_provider.remove(id4);
    ASSERT_EQ(id_provider.get_number_dirs(), 5);

    id_provider.get_id("path/one/file4.txt");

    id_provider.remove(id5);
    ASSERT_EQ(id_provider.get_number_dirs(), 5);

    id_provider.get_id("path/one/file5.txt");

    id_provider.remove(id6);
    ASSERT_EQ(id_provider.get_number_dirs(), 4);

}

TEST_F(HierarchTestFixture, TestDirCountRename) {

    auto id1 = id_provider.get_id("path/one/two/three/four/five/six/file1.txt");
    auto id2 = id_provider.get_id("path/one/file2.txt");
    auto id3 = id_provider.get_id("path/one/two/file3.txt");
    auto id4 = id_provider.get_id("path/two/four/five/file1.txt");
    auto id5 = id_provider.get_id("path/two/file2.txt");
    auto id6 = id_provider.get_id("path/two/file3.txt");

    ASSERT_EQ(id_provider.get_number_dirs(), 11);
    id_provider.remove(id1);
    auto id1_ren = id_provider.get_id("path/one/new_dir/two/three/four/five/six/file1_ren.txt");
    ASSERT_EQ(id_provider.get_number_dirs(), 13);
}

TEST_F(HierarchTestFixture, TestMultiRemove) {

    auto id1 = id_provider.get_id("path/one/two/three/four/five/six/file1.txt");
    auto id2 = id_provider.get_id("path/one/file2.txt");
    auto id3 = id_provider.get_id("path/one/two/file3.txt");
    auto id4 = id_provider.get_id("path/two/four/five/file1.txt");
    auto id5 = id_provider.get_id("path/two/file2.txt");
    auto id6 = id_provider.get_id("path/two/file3.txt");

    ASSERT_EQ(id_provider.get_number_dirs(), 11);
    id_provider.remove(id_provider.get_id("path/one/two/three/four/five/six/file1.txt"));
    ASSERT_EQ(id_provider.get_number_dirs(), 7);
    id_provider.remove(id_provider.get_id("path/one/two/three/four/five/six/file1.txt"));
    ASSERT_EQ(id_provider.get_number_dirs(), 7);
    id_provider.remove(id_provider.get_id("path/one/two/three/four/five/six/file1.txt"));
    ASSERT_EQ(id_provider.get_number_dirs(), 7);
}