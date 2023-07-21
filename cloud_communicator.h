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

//
// Created by Younis Khalil on 23.05.23.
//

#include <string>
#include "id.h"
#include <pkw/secure_byte_buffer.h>

#ifndef SECURECLOUDSTORAGE_CLOUD_COMMUNICATOR_H
namespace secure_cloud_storage {
    template<class T>
    class CloudCommunicator {
        public:
            virtual void enqueue_delete(const Id<T> &t) = 0;

            virtual void handle_delete_queue() = 0;

            virtual void write_to_cloud(const Id<T> &id,
                                        const std::vector<unsigned char> &wrapped_key,
                                        const std::vector<unsigned char> &encrypted_file,
                                        SecureByteBuffer &file_nonce) = 0;

            virtual void write_header_to_cloud(const Id<T> &id,
                                               const std::vector<unsigned char> &wrapped_key) = 0;

            virtual void write_lookup_table_to_cloud(const std::string &encrypted) = 0;

            virtual std::string read_lookup_table_from_cloud() = 0;

            virtual std::string read_from_cloud(const std::string &name) = 0;

            virtual std::string id_to_cloud_name(const Id<T> &id) = 0;

            virtual std::string id_to_cloud_header(const Id<T> &id) = 0;

            virtual size_t clean_storage(std::vector<Id<T>> known_ids) = 0;

    };
};

#define SECURECLOUDSTORAGE_CLOUD_COMMUNICATOR_H

#endif //SECURECLOUDSTORAGE_CLOUD_COMMUNICATOR_H