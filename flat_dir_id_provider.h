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

#ifndef SECURECLOUDSTORAGE_FLAT_DIR_ID_PROVIDER_H
#define SECURECLOUDSTORAGE_FLAT_DIR_ID_PROVIDER_H

#include <map>
#include <filesystem>
#include "id_provider.h"
#include "util/tag_util.h"
#include <pkw/pprf/ggm_pprf.h>

namespace secure_cloud_storage {

    class FlatDirIdProvider : public IdProvider<Tag> {
        private:
            std::map<std::filesystem::path, Id<Tag>> lookup_table;
            std::map<Id<Tag>, std::filesystem::path> reverse_lookup_table;

            int tag_len;

            std::map<std::filesystem::path, Tag> dir_id_counters;
            Tag global_id;
            std::mutex id_mutex;

            Id<Tag> get_and_increase_id_count(const std::filesystem::path &dir) {
                if (!dir_id_counters.contains(dir)) {
                    dir_id_counters[dir] = Tag(0);
                }
                id_mutex.lock();
                Tag curr_id = dir_id_counters[dir];
                if (curr_id.count() > tag_len) {
                    throw std::runtime_error("Identifiers are used up");
                }
                Tag id = curr_id;
                // inspired by https://stackoverflow.com/questions/10362991/add-1-to-c-bitset?rq=3
                for (int i = 0; i < tag_len; ++i) {
                    if (id[i] == 0) {
                        id = id.set(i, true);
                        break;
                    } else {
                        id = id.set(i, false);
                    }
                }

                Tag curr_global_id = global_id;
                // inspired by https://stackoverflow.com/questions/10362991/add-1-to-c-bitset?rq=3
                for (int i = 0; i < global_id.size(); ++i) {
                    if (global_id[i] == 0) {
                        global_id = global_id.set(i, true);
                        break;
                    } else {
                        global_id = global_id.set(i, false);
                    }
                }

                dir_id_counters[dir] = id;
                id_mutex.unlock();
                return {curr_id, tag_to_base64(curr_global_id)};
            }

        public:

            explicit FlatDirIdProvider(int tagLen) : tag_len(tagLen) {
                dir_id_counters[""] = Tag(0);
            }

            FlatDirIdProvider(const std::map<std::filesystem::path, Id<Tag>> &lookupTable, int tagLen)
                    : lookup_table(lookupTable),
                      tag_len(tagLen) {
                dir_id_counters[""] = Tag(0);
                for (auto &p: lookup_table) {
                    if (!dir_id_counters.contains(p.first.parent_path())) {
                        dir_id_counters[p.first.parent_path()] = {0};
                    }
                    reverse_lookup_table[p.second] = p.first;
                    if (dir_id_counters[p.first.parent_path()].to_string() < p.second.getLocalId().to_string()) {
                        dir_id_counters[p.first.parent_path()] = p.second.getLocalId();
                    }
                }
            }

            Id<Tag> get_id(const std::filesystem::path &path_to_file) override {
                Id<Tag> id;
                if (lookup_table.count(path_to_file)) {
                    id = lookup_table[path_to_file];
                } else {
                    // generate a fresh id
                    do {
                        id = get_and_increase_id_count(path_to_file.parent_path());
                    } while (std::any_of(reverse_lookup_table.begin(), reverse_lookup_table.end(),
                                         [&id](const auto &p) {
                                             return p.first == id;
                                         }));
                    lookup_table[path_to_file] = id;
                    reverse_lookup_table[id] = path_to_file;
                }

                return id;
            }

            std::filesystem::path get_file_path(const Id<Tag> &id) override {
                if (exists_id(id)) {
                    return reverse_lookup_table[id];
                }
                throw std::runtime_error("Tag unknown.");
            }

            bool exists_id(const Id<Tag> &id) override {
                return reverse_lookup_table.contains(id);
            }

            bool exists_file(const std::filesystem::path &p) override {
                return lookup_table.contains(p);
            }

            void remove(const Id<Tag> &id) override {
                if (exists_id(id)) {
                    std::filesystem::path p = reverse_lookup_table[id];
                    reverse_lookup_table.erase(id);
                    lookup_table.erase(p);
                }
            }

            void removeDir(const std::filesystem::path &p) {
                dir_id_counters.erase(p);
                erase_if(reverse_lookup_table, [&p](const auto &pair) {
                    return pair.second.string().starts_with(p.string());
                });

                erase_if(lookup_table, [&p](const auto &pair) {
                    return pair.first.string().starts_with(p.string());
                });
            }

            size_t size() override {
                return lookup_table.size();
            }

            std::vector<Id<Tag>> list_ids() override {
                std::vector<Id<Tag>> l;
                l.reserve(lookup_table.size());
                for (auto &p: reverse_lookup_table) {
                    l.emplace_back(p.first);
                }
                return l;
            };


    };
}

#endif //SECURECLOUDSTORAGE_FLAT_DIR_ID_PROVIDER_H