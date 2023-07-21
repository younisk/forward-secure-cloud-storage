#include "pkw/pprf/ggm_pprf.h"
#include "pkw/pprf/pprf_exceptions.h"
#include "pkw/secure_byte_buffer.h"
#include <cmath>
#include <fstream>
#include <iostream>
#include <map>
#include <sys/stat.h>

std::vector<Tag> getRands() {
    std::vector<Tag> randVec;
    std::ifstream rands("rands.txt", std::ifstream::in);
    std::string line;
    if (!rands.is_open()) {
        std::cerr << "File could not be read.";
        throw std::exception();
    }
    while (std::getline(rands, line)) {
        if (randVec.size() % 10000 == 0) {
            std::cout << "-";
        }
        randVec.emplace_back(line);
    }
    std::cout << std::endl;
    return randVec;
}

std::string writeResults(std::vector<std::tuple<int, size_t, long, long>> &serializationSizes, int tagsize) {
    std::time_t time = std::time(nullptr);
    mkdir("out", 0777);
    std::string path = "out/serializationBenchmark_tagsize" + std::to_string(tagsize) +
                       std::string(std::asctime(std::localtime(&time))) + ".txt";
    std::ofstream out(path, std::ofstream::out);
    out << "punc"
        << "\t"
        << "size"
        << "\t"
        << "punc_time"
        << "\t"
        << "eval_time"
        << std::endl;
    for (auto res: serializationSizes) {
        out << std::get<0>(res) << "\t" << std::get<1>(res) << "\t" << std::get<2>(res) << "\t" << std::get<3>(res)
            << std::endl;
    }
    out.close();
    return path;
}

int main() {
    std::cout << "Starting benchmark." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    GGM_PPRF prf(PPRFKey(256, 256));
    std::vector<Tag> rands = getRands();
    std::cout << "Read " << rands.size() << " lines." << std::endl;
    std::vector<std::tuple<int, size_t, long, long>> serializationSizes;
    auto prev = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 5000; ++i) {
        auto &rand = rands[i];
        prev = std::chrono::high_resolution_clock::now();
        prf.punc(rand >> (MAX_TAG_LEN - prf.tagLen()));
        auto curr = std::chrono::high_resolution_clock::now();
        //            SecureByteBuffer serialized = prf.serializeKey();
        auto t = (std::chrono::duration_cast<std::chrono::microseconds>(curr - prev)).count() / 10;


        try {
            auto r2 = rand.flip() & Tag((1 << 17) - 1);
            curr = std::chrono::high_resolution_clock::now();
            prf.eval(r2);
        } catch (TagException &e) {
            std::cerr << "Already punc-ed!" << std::endl;
        }
        auto eval_t = (std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::high_resolution_clock::now() - curr)).count();


        serializationSizes.emplace_back(prf.getNumPuncs(), 0, t, eval_t);
        std::cout << "Size after " << prf.getNumPuncs() << " punctures is \t" << 0
                  << ",\t avg time for 10 puncs = " << t << ",\t  time for eval = " << eval_t << std::endl;
    }
    std::cout << std::endl;

    auto end = std::chrono::high_resolution_clock::now();
    std::string path = writeResults(serializationSizes, prf.tagLen());
    std::cout << "Finished benchmark." << std::endl;
    std::cout << "Execution time: " << (std::chrono::duration_cast<std::chrono::seconds>(end - start)).count()
              << " seconds" << std::endl;
    std::cout << "Output file at: " << path;
}