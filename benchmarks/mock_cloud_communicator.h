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

#include <string>
#include <pkw/secure_byte_buffer.h>

#include "../cloud_communicator.h"


#ifndef SECURECLOUDSTORAGE_MOCKCLOUDCOMMUNICATOR_H
#define SECURECLOUDSTORAGE_MOCKCLOUDCOMMUNICATOR_H


/*
 * A cloud service adapter that does absolutely nothing.
 */
template<class T>
class MockCloudCommunicator : public secure_cloud_storage::CloudCommunicator<T> {
    public:
        void enqueue_delete(const Id<T> &t) override {

        }

        void handle_delete_queue() override {

        }

        void write_to_cloud(const Id<T> &id, const std::vector<unsigned char> &wrapped_key,
                            const std::vector<unsigned char> &encrypted_file, SecureByteBuffer &file_nonce) override {

        }

        void write_header_to_cloud(const Id<T> &id, const std::vector<unsigned char> &wrapped_key) override {

        }

        std::string read_from_cloud(const std::string &name) override {
            return {};
        }

        std::string id_to_cloud_name(const Id<T> &id) override {
            return {};
        }

        std::string id_to_cloud_header(const Id<T> &id) override {
            return {};
        }

        size_t clean_storage(std::vector<Id<T>> known_ids) override {
            return 0;
        }
};

#endif //SECURECLOUDSTORAGE_MOCKCLOUDCOMMUNICATOR_H