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
#include <fstream>
#include <google/cloud/storage/client.h>
#include "../client_operator.h"
#include "../util/file_util.h"
#include "../gcs_cloud_communicator.h"
#include "../flat_id_provider.h"
#include <pkw/pkw/pprf_aead_pkw.h>

const std::string bucket_name = "secure-cloud-storage-test";
namespace scs = secure_cloud_storage;
namespace gcs = ::google::cloud::storage;

class ClientOperatorTest : public ::testing::Test {
    public:
    protected:
        void TearDown() override {
            for (auto &i: co.list_files()) {
                co.shred(co.get_id(i));
            }
        }

        ClientOperatorTest() : co(256, 256, std::make_unique<scs::GCSCloudCommunicator<Tag>>(bucket_name),
                                  std::make_shared<secure_cloud_storage::FlatIdProvider>(256),
                                  std::make_unique<PPRF_AEAD_PKW>(256, 256)) {};
    protected:
        scs::ClientOperator<Tag> co;

};

static void clear_bucket() {
    auto client = gcs::Client();
    for (auto &ob: client.ListObjects(bucket_name)) {
        client.DeleteObject(bucket_name, ob->name());
    }
}

TEST_F(ClientOperatorTest, PutTest) {
    const std::string filename = "resources/lorem_ipsum.txt";
    std::vector<unsigned char> content = scs::FileUtil::read_file(filename);
    Id<Tag> id = co.put(std::filesystem::path(filename), content);
    ASSERT_EQ(co.get_file_name(id), filename);
    ASSERT_EQ(co.get_id(filename), id);

}

TEST_F(ClientOperatorTest, PutAndGetTest) {
    const std::string file_name = "resources/lorem_ipsum.txt";
    std::vector<unsigned char> content = scs::FileUtil::read_file(file_name);
    Id<Tag> id = co.put(std::filesystem::path(file_name), content);
    const std::vector<unsigned char> file_contents = co.get(id);
    std::ifstream f(file_name, std::ios::in);
    std::vector<unsigned char> expected_contents((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    ASSERT_EQ(file_contents, expected_contents) << "File contents differ.";
}

TEST_F(ClientOperatorTest, PutTwiceSameId) {
    const std::string filename = "resources/lorem_ipsum.txt";
    auto content = scs::FileUtil::read_file(filename);
    Id<Tag> id1 = co.put(std::filesystem::path(filename), content);
    Id<Tag> id2 = co.put(std::filesystem::path(filename), content);
    ASSERT_EQ(id1, id2);
}

TEST(ClientOperatorRotateTest, RotateKeys) {
    clear_bucket();
    auto co = scs::ClientOperator<Tag>(256, 256,
                                       std::make_shared<secure_cloud_storage::GCSCloudCommunicator<Tag>>(bucket_name),
                                       std::make_shared<secure_cloud_storage::FlatIdProvider>(256),
                                       std::make_unique<PPRF_AEAD_PKW>(256, 256));
    const std::string filename = "resources/lorem_ipsum.txt";
    auto content = scs::FileUtil::read_file(filename);
    Id<Tag> id1 = co.put(std::filesystem::path("file1"), content);
    Id<Tag> id2 = co.put(std::filesystem::path("file2"), content);
    Id<Tag> id3 = co.put(std::filesystem::path("file3"), content);
    co.shred(id2);
    ASSERT_THROW(co.get(id2), std::exception);
    co.rotate_keys(std::make_unique<PPRF_AEAD_PKW>(256, 256));
    // Assert that current number of files is 2, so 2 files can be deleted from the cloud
    ASSERT_EQ(co.clean(), 2);
    auto content_1 = co.get(id1);
    ASSERT_EQ(content_1, content);
    ASSERT_THROW(co.get(id2), std::exception);
    auto content_3 = co.get(id3);
    ASSERT_EQ(content_3, content);

}


TEST(ClientOperatorCleanTest, Clean) {
    clear_bucket();
    auto co = scs::ClientOperator<Tag>(256, 256,
                                       std::make_shared<secure_cloud_storage::GCSCloudCommunicator<Tag>>(bucket_name),
                                       std::make_shared<secure_cloud_storage::FlatIdProvider>(256),
                                       std::make_unique<PPRF_AEAD_PKW>(256, 256));
    const std::string filename = "resources/lorem_ipsum.txt";
    auto content = scs::FileUtil::read_file(filename);
    Id<Tag> id1 = co.put(std::filesystem::path("file1"), content);
    Id<Tag> id2 = co.put(std::filesystem::path("file2"), content);
    Id<Tag> id3 = co.put(std::filesystem::path("file3"), content);
    ASSERT_EQ(co.clean(), 0);
}