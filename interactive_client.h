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
// Created by Younis Khalil on 20.01.23.
//

#ifndef SECURECLOUDSTORAGE_INTERACTIVE_CLIENT_H
#define SECURECLOUDSTORAGE_INTERACTIVE_CLIENT_H

#include <string>

namespace secure_cloud_storage {
    const std::string default_settings_dir = ".cli/";
    const std::string key_filename = "pkw.key";
    const std::string lookup_table_ratchet_key_filename = "lookup.key";
    const std::string properties_filename = "properties.cli";
    const int default_key_len = 256;
    const int default_tag_len = 256;
} // namespace secure_cloud_storage

#endif //SECURECLOUDSTORAGE_INTERACTIVE_CLIENT_H