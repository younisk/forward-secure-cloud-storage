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
#include "../client_operator.h"
#include "benchmark_local_hierarch_client.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <utility>

namespace fs = std::filesystem;


static const std::string ADD = "A";
static const std::string MODIFY = "M";
static const std::string DELETE = "D";
static const std::string RENAME = "R100";
static const std::string DIR_DELETE = "DD";


struct FileAction {
    std::string action;
    std::string fileName;

    FileAction(std::string a, std::string fname) : action(std::move(a)), fileName(std::move(fname)) {};
};


std::vector<FileAction> loadGitHistory(const std::string &path) {
    if (!fs::exists(path) || !fs::is_regular_file(path)) {
        throw std::runtime_error("File does not exist: " + path);
    }

    auto actions = std::vector<FileAction>();

    std::ifstream infile(path, std::ios::in);
    std::string line;
    int lcount = 0;
    while (std::getline(infile, line)) {
        lcount++;
        std::istringstream iss(line);
        std::string mode_string;
        std::string filename;
        std::string filenameNew;
        if (!(iss >> mode_string >> filename)) {
            std::cerr << "Something went wrong at line " << lcount << std::endl;
        }
        std::string mode = mode_string;
        if (mode == RENAME) {
            if (!(iss >> filenameNew)) {
                std::cerr << "Something went wrong at line " << lcount << std::endl;
            }
        }
        if (mode == ADD || mode == MODIFY || mode == DELETE || mode == DIR_DELETE) {
            actions.emplace_back(mode, filename);
        } else if (mode == RENAME) {
            actions.emplace_back(DELETE, filename);
            actions.emplace_back(ADD, filenameNew);
        } else {
            std::cerr << "Unknown mode: " << line << std::endl;
        }

    }
    return actions;
}

std::vector<unsigned char> empty;

std::string get_date_string() {
    auto start = std::chrono::system_clock::now();
    auto start_t = std::chrono::system_clock::to_time_t(start);
    auto start_tm = std::localtime(&start_t);
    char date_string[100];
    std::strftime(date_string, 100, "%Y_%m_%d_%Hh%M", start_tm);
    std::string date_copy(date_string);
    return date_copy;
}

int main() {
    auto co = scs_benchmarks::BenchmarkLocalClientOperator(256);
    auto outputDir = fs::path("git_bench_results");
    fs::create_directories(outputDir);
    std::string gitHistFileName = "freeCodeCamp_git_hist_with_dir_deletes.txt";

    std::vector<FileAction> gitHistory = loadGitHistory("resources/" + gitHistFileName);

    auto outFile = std::ofstream(outputDir / (gitHistFileName + "_" + get_date_string() + ".csv"));
    outFile << "action" << "," << "t" << "," << "filename" << "," << "key_size" << "," << "numDirs" << std::endl;

    unsigned long key_size = co.export_key().size();
    int i = 0;

    for (auto &ac: gitHistory) {
        auto curr = std::chrono::high_resolution_clock::now();
        try {
            if (ac.action == ADD || ac.action == MODIFY) {
                // different action depending on replay protection
                co.put(fs::path(ac.fileName), empty);
            } else if (ac.action == DELETE || ac.action == DIR_DELETE) {
                co.shred(co.get_id(ac.fileName));
            }

        } catch (std::runtime_error &e) {
            std::cerr << "Problem with action " << ac.action << " for file " << ac.fileName << std::endl;
            continue;
        }
        auto diff = std::chrono::high_resolution_clock::now() - curr;

        if (i % 1000 == 999) {
            key_size = co.export_key().size();
        }
        ++i;

        outFile << ac.action << "," << diff.count() << "," << ac.fileName
                << "," << key_size << "," << co.get_number_dirs() << std::endl;
    }

    auto outKey = std::ofstream(outputDir / (gitHistFileName + "_" + get_date_string() + "_key.bin"));
    auto k = co.export_key();
    outKey << std::string(k.begin(), k.end());
    return 0;
}