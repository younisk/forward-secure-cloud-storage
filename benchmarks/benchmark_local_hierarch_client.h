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

/**
 * Removes any communication with cloud from client. For benchmarking cryptographic operations.
 */
#include "../client_operator.h"
#include "mock_cloud_communicator.h"
#include "../hierarch_id_provider.h"
#include "pkw/pkw/hpprf_aead_pkw.h"

#ifndef SECURECLOUDSTORAGE_BENCHMARK_LOCAL_CLIENT_H
namespace scs_benchmarks {
    class BenchmarkLocalClientOperator : public secure_cloud_storage::ClientOperator<Tag> {
        public:
            explicit BenchmarkLocalClientOperator(int keyLen) : ClientOperator(1, keyLen,
                                                                               std::make_shared<MockCloudCommunicator<Tag>>(),
                                                                               std::make_shared<secure_cloud_storage::HierarchIdProvider>(),
                                                                               std::make_shared<HPPRF_AEAD_PKW>(
                                                                                       keyLen)) {}

            size_t get_number_dirs() const {
                return std::dynamic_pointer_cast<secure_cloud_storage::HierarchIdProvider>(
                        id_provider)->get_number_dirs();
            }
    };
}

#define SECURECLOUDSTORAGE_BENCHMARK_LOCAL_CLIENT_H

#endif //SECURECLOUDSTORAGE_BENCHMARK_LOCAL_CLIENT_H