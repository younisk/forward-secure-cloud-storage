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

#ifndef SECURECLOUDSTORAGE_GCS_CLOUD_COMMUNICATOR_H
#define SECURECLOUDSTORAGE_GCS_CLOUD_COMMUNICATOR_H

#include "cloud_communicator.h"
#include <google/cloud/storage/client.h>


#define MAX_DELETE_QUEUE_SIZE 20

namespace secure_cloud_storage {

    template<class T>
    class GCSCloudCommunicator : public CloudCommunicator<T> {

        public:

            explicit GCSCloudCommunicator(std::string bucketName) : bucket_name(bucketName) {}


            void enqueue_delete(const Id<T> &t) override {
                delete_queue.emplace_back(id_to_cloud_name(t));
                delete_queue.emplace_back(id_to_cloud_header(t));
            }

            size_t clean_storage(std::vector<Id<T>> known_ids) override {
                std::vector<std::string> to_delete;
                for (auto o: client.ListObjects(bucket_name)) {
                    std::string filename = o->name();
                    const std::string remoteId = filename.substr(0, filename.length() - 2);
                    if (std::none_of(known_ids.begin(), known_ids.end(), [&remoteId](const auto &id) {
                        return id.getRemoteId() == remoteId;
                    })) {
                        to_delete.emplace_back(filename);
                    }
                }
                for (auto &i: to_delete) {
                    if (!std::count(delete_queue.begin(), delete_queue.end(), i)) {
                        delete_queue.push_back(i);
                    }
                }
                unsigned long size = delete_queue.size();
                clear_delete_queue();
                return size;
            }

            void write_header_to_cloud(const Id<T> &id, const std::vector<unsigned char> &wrapped_key) override {
                auto header_writer = client.WriteObject(bucket_name, id_to_cloud_header(id));
                header_writer << std::string(wrapped_key.begin(), wrapped_key.end());
                header_writer.Close();
            }

            void handle_delete_queue() override {
                if (delete_queue.size() > MAX_DELETE_QUEUE_SIZE) {
                    clear_delete_queue();
                }
            }

            void write_to_cloud(const Id<T> &id, const std::vector<unsigned char> &wrapped_key,
                                const std::vector<unsigned char> &encrypted_file,
                                SecureByteBuffer &file_nonce) override {
                // first write the nonce, then ciphertext
                auto file_write = std::async([this, &id, &file_nonce, &encrypted_file]() -> void {
                    auto file_writer = client.WriteObject(bucket_name, id_to_cloud_name(id));
                    file_writer << std::string(file_nonce.begin(), file_nonce.end());
                    file_writer << std::string(encrypted_file.begin(), encrypted_file.end());
                    file_writer.Close();
                });

                // then write the header, i.e. the wrapped dek
                auto header_write = std::async([this, &id, &wrapped_key]() -> void {
                    auto header_writer = client.WriteObject(bucket_name, id_to_cloud_header(id));
                    header_writer << std::string(wrapped_key.begin(), wrapped_key.end());;
                    header_writer.Close();
                });
                file_write.get();
                header_write.get();
            }

            std::string read_from_cloud(const std::string &name) override {

                auto file_reader = client.ReadObject(bucket_name, name);
                if (!file_reader) {
                    throw std::runtime_error("Cannot find file for id " + name);
                }
                std::string contents(std::istreambuf_iterator<char>{file_reader}, {});
                return contents;
            }

            std::string id_to_cloud_name(const Id<T> &id) override {
                return id.getRemoteId() + ".f";
            }

            std::string id_to_cloud_header(const Id<T> &id) override {
                return id.getRemoteId() + ".h";
            }

            void write_lookup_table_to_cloud(const std::string &encrypted) override {
                auto writer = client.WriteObject(bucket_name, "T");
                writer << encrypted;
                writer.Close();
            }

            std::string read_lookup_table_from_cloud() override {
                return read_from_cloud("T");
            }

        private:
            std::string bucket_name;
            std::vector<std::string> delete_queue;
            google::cloud::storage::Client client;

            void clear_delete_queue() {
                std::__1::vector<std::__1::future<google::cloud::Status>> threads;
                for (auto &item: delete_queue) {
                    auto del_item = std::async(std::launch::async, [this, item]() -> google::cloud::Status {
                        return google::cloud::storage::Client().DeleteObject(bucket_name, item);
                    });
                    threads.push_back(std::move(del_item));
                }
                for (auto &t: threads) {
                    if (!t.get().ok()) {
                        throw std::runtime_error("Could not delete an item");
                    }
                }
                delete_queue.clear();
            }
    };

} // secure_cloud_storage

#endif //SECURECLOUDSTORAGE_GCS_CLOUD_COMMUNICATOR_H