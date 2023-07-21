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

#include <fstream>
#include <cryptopp/rdrand.h>
#include <pkw/pkw/pprf_aead_pkw.h>
#include "../client_operator.h"
#include "../util/file_util.h"
#include "benchmark_client_operator.h"
#include "../gcs_cloud_communicator.h"
#include "../flat_id_provider.h"

namespace scs = secure_cloud_storage;
namespace fs = std::filesystem;
namespace bench = scs_benchmarks;

const std::string bucket_name = "secure-cloud-storage-test";


const fs::path test_files_path = fs::path("data/");
const fs::path small_file_name = test_files_path / "small.txt";
const fs::path large_file_name = test_files_path / "large.txt";

static void clear_bucket() {
    auto client = gcs::Client();
    for (auto &ob: client.ListObjects(bucket_name)) {
        client.DeleteObject(bucket_name, ob->name());
    }
}

/* Benchmark putting small files */
const int small_put_limit = 100;

static void baseline_bench_put_small_256(fs::path &output_dir) {
    bench::ClientOperator co(bucket_name);
    co.clear();
    auto content = scs::FileUtil::read_file(small_file_name);

    auto curr = std::chrono::high_resolution_clock::now();
    auto out_file = std::ofstream(output_dir / "put_small_256_256_baseline.txt", std::ios::out);
    for (int i = 1; i < small_put_limit; ++i) {
        co.put(fs::path("bench") / fs::path("small" + std::to_string(i) + ".txt"), content);
        auto diff = std::chrono::high_resolution_clock::now() - curr;
        out_file << diff.count() << std::endl;
        curr = std::chrono::high_resolution_clock::now();

    }
    out_file.close();
}

static void bench_put_small_256(fs::path &output_dir) {
    scs::ClientOperator<Tag> co(256, 256, std::make_shared<scs::GCSCloudCommunicator<Tag>>(bucket_name),
                                std::make_shared<scs::FlatIdProvider>(256),
                                std::make_shared<PPRF_AEAD_PKW>(256, 256));
    auto content = scs::FileUtil::read_file(small_file_name);

    auto curr = std::chrono::high_resolution_clock::now();
    auto out_file = std::ofstream(output_dir / "put_small_256_256.txt", std::ios::out);
    for (int i = 1; i < small_put_limit; ++i) {
        co.put(small_file_name / std::to_string(i), content);
        auto diff = std::chrono::high_resolution_clock::now() - curr;
        out_file << diff.count() << std::endl;
        curr = std::chrono::high_resolution_clock::now();

    }
    out_file.close();
}


/* Benchmark putting large files */
const int large_put_limit = 100;

static void baseline_bench_put_large_256(fs::path &output_dir) {
    bench::ClientOperator co(bucket_name);
    co.clear();
    auto content = scs::FileUtil::read_file(large_file_name);

    auto curr = std::chrono::high_resolution_clock::now();
    auto out_file = std::ofstream(output_dir / "put_large_256_256_baseline.txt", std::ios::out);
    for (int i = 1; i < large_put_limit; ++i) { ;
        co.put(fs::path("bench") / fs::path("large" + std::to_string(i) + ".txt"), content);
        auto diff = std::chrono::high_resolution_clock::now() - curr;
        out_file << diff.count() << std::endl;
        curr = std::chrono::high_resolution_clock::now();

    }
    out_file.close();
}


static void bench_put_large_256(fs::path &output_dir) {
    scs::ClientOperator<Tag> co(256, 256, std::make_shared<scs::GCSCloudCommunicator<Tag>>(bucket_name),
                                std::make_shared<scs::FlatIdProvider>(256),
                                std::make_unique<PPRF_AEAD_PKW>(256, 256));
    auto content = scs::FileUtil::read_file(large_file_name);
    auto curr = std::chrono::high_resolution_clock::now();
    auto out_file = std::ofstream(output_dir / "put_large_256_256.txt", std::ios::out);
    for (int i = 1; i < large_put_limit; ++i) {
        co.put(large_file_name / std::to_string(i), content);
        auto diff = std::chrono::high_resolution_clock::now() - curr;
        out_file << diff.count() << std::endl;
        curr = std::chrono::high_resolution_clock::now();

    }
    out_file.close();
}


/* Benchmark deleting small files */
const int delete_limit = 100;

static void baseline_bench_delete_256(fs::path &output_dir) {
    bench::ClientOperator co(bucket_name);
    co.clear();
    std::vector<unsigned char> content{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'a', 'b', 'c', 'd', 'e', 'f'};


    auto out_file = std::ofstream(output_dir / "delete_256_256_baseline.txt", std::ios::out);

    //setup
    for (int i = 1; i < delete_limit; ++i) {
        fs::path file = fs::path("bench") / fs::path("small" + std::to_string(i) + ".txt");
        co.put(file, content);
    }

    auto curr = std::chrono::high_resolution_clock::now();
    for (int i = 1; i < delete_limit; ++i) {
        fs::path file = fs::path("bench") / fs::path("small" + std::to_string(i) + ".txt");
        curr = std::chrono::high_resolution_clock::now();
        co.shred(file);
        auto diff = std::chrono::high_resolution_clock::now() - curr;
        out_file << diff.count() << std::endl;

    }
    out_file.close();
}


static void bench_delete_256(fs::path &output_dir) {
    scs::ClientOperator<Tag> co(256, 256, std::make_shared<scs::GCSCloudCommunicator<Tag>>(bucket_name),
                                std::make_shared<scs::FlatIdProvider>(256),
                                std::make_unique<PPRF_AEAD_PKW>(256, 256));
    std::vector<unsigned char> content{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'a', 'b', 'c', 'd', 'e', 'f'};

    //setup
    std::vector<Id<Tag>> ids;
    for (int i = 1; i < delete_limit; ++i) { ;
        auto t = co.put(small_file_name / std::to_string(i), content);
        ids.push_back(t);
    }

    auto curr = std::chrono::high_resolution_clock::now();
    auto out_file = std::ofstream(output_dir / "delete_256_256.txt", std::ios::out);
    for (Id<Tag> &t: ids) {
        curr = std::chrono::high_resolution_clock::now();
        co.shred(t);
        auto diff = std::chrono::high_resolution_clock::now() - curr;
        out_file << diff.count() << std::endl;

    }
    out_file.close();
}

/* Benchmark rotating keys */
const int rot_key_limit = 100;

const std::vector<int> bench_iters({1000, 2000});

static void bench_rot_keys_256(fs::path &output_dir) {
    scs::ClientOperator<Tag> co(256, 256, std::make_shared<scs::GCSCloudCommunicator<Tag>>(bucket_name),
                                std::make_shared<scs::FlatIdProvider>(256),
                                std::make_unique<PPRF_AEAD_PKW>(256, 256));
    std::vector<unsigned char> content{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'a', 'b', 'c', 'd', 'e', 'f'};

    //setup
    std::vector<Id<Tag>> ids;
    for (int i = 1; i < rot_key_limit; ++i) { ;
        auto t = co.put(small_file_name / std::to_string(i), content);
        ids.push_back(t);
    }

    auto out_file = std::ofstream(output_dir / "rot_keys_256_256.txt", std::ios::out);
    for (int iter: bench_iters) {
        for (int i = 0; i < iter; ++i) {
            auto t = co.put(small_file_name / ("a" + std::to_string(i)), content);
            co.shred(t);
        }
        std::this_thread::sleep_for(std::chrono::seconds(20));
        auto curr = std::chrono::high_resolution_clock::now();
        std::cout << "Rotated keys for " << co.rotate_keys(std::make_shared<PPRF_AEAD_PKW>(256, 256))
                  << " objects." << std::endl;
        auto diff = std::chrono::high_resolution_clock::now() - curr;
        out_file << diff.count() << std::endl;
    }
    out_file.close();
}

Tag generate_random_id(int tag_len) {
    Tag rand;
    CryptoPP::RDRAND prng;
    for (int i = 0; i < tag_len; ++i) {
        rand.set(i, prng.GenerateBit());
    }
    return rand;
}

static void bench_rot_keys_only_PKW_256(fs::path &output_dir) {
    auto pkw = PPRF_AEAD_PKW(256, 256);

    //setup
    std::vector<Tag> ids;
    std::vector<std::vector<unsigned char>> keys;
    std::vector<unsigned char> h{0};
    std::vector<unsigned char> key(256);
    for (int i = 1; i < rot_key_limit; ++i) { ;
        Tag t = generate_random_id(256);
        ids.push_back(t);
        keys.emplace_back(pkw.wrap(t, h, key));
    }

    auto out_file = std::ofstream(output_dir / "rot_keys_256_256_baseline.txt", std::ios::out);
    for (int iter: bench_iters) {
        for (int i = 0; i < iter; ++i) {
            Tag t;
            do {
                t = generate_random_id(256);
            } while (std::count(ids.begin(), ids.end(), t) > 0);
            pkw.punc(t);
        }

        auto curr = std::chrono::high_resolution_clock::now();
        auto pkw_new = PPRF_AEAD_PKW(256, 256);
        for (int j = 0; j < ids.size(); ++j) {
            auto k = pkw.unwrap(ids[j], h, keys[j]);
            keys[j] = pkw_new.wrap(ids[j], h, k);
        }
        pkw = pkw_new;
        auto diff = std::chrono::high_resolution_clock::now() - curr;
        out_file << diff.count() << std::endl;
    }
    out_file.close();
}

/* Run benchmarks */
int main() {
    auto start = std::chrono::system_clock::now();
    auto start_t = std::chrono::system_clock::to_time_t(start);
    auto start_tm = std::localtime(&start_t);
    char date_string[100];
    std::strftime(date_string, 100, "%Y_%m_%d_%Hh%M", start_tm);
    std::string date_copy(date_string);
    fs::path output_dir("./results/" + date_copy);
    fs::create_directories(output_dir);

    std::cout << "Starting benchmarks, outputs located at: " << output_dir << std::endl;
//
//    clear_bucket();
//    std::cout << "Running baseline for put (small)" << std::endl;
//    baseline_bench_put_small_256(output_dir);
//    std::cout << "Running benchmark for put (small)" << std::endl;
//    bench_put_small_256(output_dir);
//
//    clear_bucket();
//    std::cout << "Running baseline for put (large)" << std::endl;
//    baseline_bench_put_large_256(output_dir);
//    std::cout << "Running benchmark for put (large)" << std::endl;
//    bench_put_large_256(output_dir);
//
//    clear_bucket();
//    std::cout << "Running baseline for delete" << std::endl;
//    baseline_bench_delete_256(output_dir);
//    std::cout << "Running benchmark for delete" << std::endl;
//    bench_delete_256(output_dir);

    clear_bucket();
    std::cout << "Running benchmark for rotating keys" << std::endl;
    bench_rot_keys_256(output_dir);
    bench_rot_keys_only_PKW_256(output_dir);

    std::cout << "Done. Benchmarks took "
              << std::to_string(std::chrono::duration_cast<std::chrono::minutes>(
                      (std::chrono::system_clock::now() - start)).count())
              << " minutes" << std::endl;
}