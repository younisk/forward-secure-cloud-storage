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

#ifndef SECURECLOUDSTORAGE_ID_PROVIDER_H
#define SECURECLOUDSTORAGE_ID_PROVIDER_H

#include "id.h"
#include <filesystem>


namespace secure_cloud_storage {

    template<class T>
    class IdProvider {
        public:
            virtual Id<T> get_id(const std::filesystem::path &path_to_file) = 0;

            virtual std::filesystem::path get_file_path(const Id<T> &id) = 0;

            virtual bool exists_id(const Id<T> &id) = 0;

            virtual bool exists_file(const std::filesystem::path &p) = 0;

            virtual void remove(const Id<T> &id) = 0;

            virtual size_t size() = 0;

            virtual std::vector<Id<T>> list_ids() = 0;
    };
}

#endif //SECURECLOUDSTORAGE_ID_PROVIDER_H