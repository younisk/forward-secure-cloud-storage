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
// Created by Younis Khalil on 03.02.23.
//

#ifndef SECURECLOUDSTORAGE_BENCHMARK_CLIENT_OPERATOR_H
#define SECURECLOUDSTORAGE_BENCHMARK_CLIENT_OPERATOR_H

#include <string>
#include <filesystem>
#include <google/cloud/storage/client.h>

namespace gcs = google::cloud::storage;

namespace scs_benchmarks {
    /**
     * Mock ClientOperator which does no encryption; to establish baselines.
     */
    class ClientOperator {
        private:
            std::string bucket_name;
        public:
            explicit ClientOperator(std::string bucket_name) : bucket_name(std::move(bucket_name)) {};

            void put(const std::filesystem::path &file_name, std::vector<unsigned char> &file_content);

            std::vector<unsigned char> get(const std::string &file_name);

            void shred(const std::string &file_name);

            void clear();
    };

    void ClientOperator::put(const std::filesystem::path &file_name, std::vector<unsigned char> &file_content) {
        auto client = gcs::Client();
        auto file_writer = client.WriteObject(bucket_name, std::filesystem::path("bench") / file_name);
        file_writer.Close();
    }

    std::vector<unsigned char> ClientOperator::get(const std::string &file_name) {
        auto client = gcs::Client();
        // first write the encrypted file, with the nonce appended
        auto file_reader = client.ReadObject(bucket_name, std::filesystem::path("bench") / file_name);
        if (!file_reader) {
            throw std::runtime_error("Cannot find file for id " + file_name);
        }
        std::vector<unsigned char> contents(std::istreambuf_iterator<char>{file_reader}, {});
        return contents;
    }

    void ClientOperator::shred(const std::string &file_name) {
        auto client = gcs::Client();
        client.DeleteObject(bucket_name, std::filesystem::path("bench") / file_name);
    }

    void ClientOperator::clear() {
        auto client = gcs::Client();
        client.DeleteObject(bucket_name, std::filesystem::path("bench"));
    }
};


#endif //SECURECLOUDSTORAGE_BENCHMARK_CLIENT_OPERATOR_H