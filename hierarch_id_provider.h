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

#ifndef SECURECLOUDSTORAGE_HIERARCH_ID_PROVIDER_H
#define SECURECLOUDSTORAGE_HIERARCH_ID_PROVIDER_H


#include <pkw/pkw/hpprf_aead_pkw.h>
#include <filesystem>
#include <vector>
#include <deque>
#include <string>
#include <map>
#include <set>
#include "id_provider.h"

#define MAX_DIR_SIZE 16 // 2^16 == 65k, fat32 limit to num. files per directory

namespace secure_cloud_storage {

    namespace fs = std::filesystem;

    const static int MARK_FILE = -1;

    class HierarchIdProvider : public IdProvider<Tag> {
        public:
            HierarchIdProvider() {
                Id<Tag> root({}, "");
                lookup_table[""] = {root, 0};
                reverse_lookup_table[root] = "";
                pathChildren[""] = {};
            }

            Id<Tag> get_id(const fs::path &path_to_file) override {
                if (exists_path(path_to_file)) {
                    return lookup_table[path_to_file].first;
                }
                if (lookup_table.empty()) {
                    throw std::runtime_error("root has been punctured!");
                }
                handle_new_path(path_to_file);

                if (!exists_path(path_to_file.parent_path())) {
                    throw std::runtime_error("Cannot find parent directory identifier");
                }
                auto idCtr = lookup_table[path_to_file.parent_path()];
                // construct Id<Tag> from concatenation of directory tag and file counter
                Tag full_t = idCtr.first.getLocalId();
                Tag file_t = int2tag(idCtr.second);
                full_t.insert(full_t.end(), file_t.begin(), file_t.end());

                long long remoteId = remoteIdCtr.fetch_add(1);
                Id id(full_t, std::to_string(remoteId));

                lookup_table[path_to_file.parent_path()] = {idCtr.first, idCtr.second + 1};
                lookup_table[path_to_file] = {id, MARK_FILE};
                reverse_lookup_table[id] = path_to_file;
                pathChildren[path_to_file.parent_path()].insert(path_to_file);
                return id;
            }

            std::filesystem::path get_file_path(const Id<Tag> &id) override {
                if (!exists_id(id)) {
                    throw std::runtime_error("Requested path for unknown id.");
                }
                return reverse_lookup_table[id];
            }

            bool exists_id(const Id<Tag> &id) override {
                return reverse_lookup_table.count(id) > 0;
            }

            bool exists_file(const std::filesystem::path &p) override {
                return exists_path(p);
            }

            bool exists_path(const std::filesystem::path &p) {
                return lookup_table.count(p) > 0;
            }

            void remove(const Id<Tag> &id) override {
                if (!exists_id(id)) {
                    return;
                }
                fs::path path = reverse_lookup_table[id];

                // Find all paths that need to be removed
                std::vector<std::filesystem::path> allChildren = findAllChildren(path);

                // remove all (transitive) children
                for (auto &p: allChildren) {
                    const Id<Tag> &pId = get_id(p);
                    reverse_lookup_table.erase(pId);
                    lookup_table.erase(p);
                    pathChildren.erase(p);
                }

                // remove path itself
                reverse_lookup_table.erase(id);
                lookup_table.erase(path);
                pathChildren.erase(path);


                // remove empty directories
                bool atRoot = path.empty();
                if (atRoot) {
                    return;
                }

                // remove path from parent
                auto parentPath = path.parent_path();
                pathChildren[parentPath].erase(path);

                while (pathChildren[parentPath].empty() && !atRoot) {
                    // remove the empty directory
                    pathChildren.erase(parentPath);
                    // move up one level
                    path = parentPath;
                    parentPath = parentPath.parent_path();
                    if (parentPath.empty()) {
                        atRoot = true;
                    }
                    // get the children from the new parent and remove directory
                    pathChildren[parentPath].erase(path);
                    auto idDir = lookup_table[path];
                    // also remove empty dir from lookup tables
                    lookup_table.erase(path);
                    reverse_lookup_table.erase(idDir.first);
                }
            }

            size_t size() override {
                return lookup_table.size();
            }

            std::vector<Id<Tag>> list_ids() override {
                // return ids for files, not directories: files always have an id counter of -1 (they are not directories)
                std::vector<Id<Tag>> ids;
                for (auto &p: lookup_table) {
                    if (p.second.second == MARK_FILE) {
                        ids.emplace_back(p.second.first);
                    }
                }
                return ids;
            }

            size_t get_number_dirs() {
                return pathChildren.size();
            }

        private:
            // the pair contains the identifier for the directory and the file id counter
            std::map<std::filesystem::path, std::pair<Id<Tag>, int>> lookup_table;
            std::map<Id<Tag>, std::filesystem::path> reverse_lookup_table;

            // optimization for deletion
            std::map<std::filesystem::path, std::set<std::filesystem::path>> pathChildren;


//            std::mutex id_mutex;
            std::atomic<long long> remoteIdCtr;

            static Tag int2tag(int i) {
                std::bitset<MAX_DIR_SIZE> bs(i);
                Tag t(bs.size());
                for (int j = 0; j < bs.size(); j++) {
                    t[j] = bs[bs.size() - 1 - j];
                }
                return t;
            }

            // handle new path to a file
            void handle_new_path(fs::path p) {
                std::deque<fs::path> new_dirs;
                while (!p.empty()) {
                    p = p.parent_path();
                    if (!exists_path(p)) {
                        // have to go the other way!
                        new_dirs.emplace_front(p);
                    }
                }
                /* new_dirs should be ordered such that the unknown path closest to the root is
                 * first in the list: then the paths can be iteratively added to the lookup table (and be sure that the
                 * parent path is already there */
                for (auto &new_dir: new_dirs) {
                    auto idCtr = lookup_table[new_dir.parent_path()];
                    if (idCtr.second == MARK_FILE) {
                        throw std::runtime_error(
                                "Attempting to add directory with same name as file. This is disallowed.");
                    }
                    // update the parent path directory counter
                    lookup_table[new_dir.parent_path()] = {idCtr.first, idCtr.second + 1};

                    Tag full_id = idCtr.first.getLocalId();
                    Tag new_dir_tag = int2tag(idCtr.second);
                    full_id.insert(full_id.end(), new_dir_tag.begin(), new_dir_tag.end());
                    Id id(full_id, std::to_string(remoteIdCtr.fetch_add(1)));
                    lookup_table[new_dir] = {id, 0};
                    reverse_lookup_table[id] = new_dir;
                    pathChildren[new_dir.parent_path()].insert(new_dir);
                }
            }

            std::vector<std::filesystem::path> findAllChildren(const fs::path &p) {
                if (pathChildren.count(p) == 0) {
                    return {};
                }
                std::vector<std::filesystem::path> all;
                for (auto &child: pathChildren[p]) {
                    all.emplace_back(child);
                    const auto &childChildren = findAllChildren(child);
                    all.insert(all.end(), childChildren.begin(), childChildren.end());
                }
                return all;
            }
    };
//
//    std::vector<std::filesystem::path> HierarchIdProvider::findAllChildren(const fs::path &p)
}


#endif //SECURECLOUDSTORAGE_HIERARCH_ID_PROVIDER_H