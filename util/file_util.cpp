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

#include "file_util.h"
#include <fstream>

namespace fs = std::filesystem;

namespace secure_cloud_storage {
    void FileUtil::write_file(std::vector<unsigned char> &contents, bool overwrite, const fs::path &path) {
        if (fs::exists(path) && !overwrite) {
            throw std::runtime_error("File exists but should not be overwritten: " + path.string());
        }
        // check whether directory exists - if not create all directory needed for the path
        if (!fs::exists(path.parent_path())) {
            if (!fs::create_directories(path)) {
                throw std::runtime_error("Could not create directory " + path.parent_path().string());
            }
        }
        std::ofstream f(path, std::ios::out);
        f << std::string{contents.begin(), contents.end()};
    }

    std::vector<unsigned char> FileUtil::read_file(const fs::path &path) {
        if (!fs::exists(path) || !fs::is_regular_file(path)) {
            throw std::runtime_error("File does not exist: " + path.string());
        }
        std::ifstream f(path, std::ios::in);
        return {(std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>()};
    }
} // secure_cloud_storage