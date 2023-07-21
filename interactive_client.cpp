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

#include <cli/cli.h>
#include <cli/clilocalsession.h>
#include <cli/loopscheduler.h>
#include <filesystem>
#include <fstream>
#include "client_operator.h"
#include "interactive_client.h"
#include "util/file_util.h"
#include "gcs_cloud_communicator.h"
#include "flat_id_provider.h"
#include <pkw/pkw/pprf_aead_pkw.h>
#include <pkw/pkw/helpers/password_encrypt.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>

using namespace secure_cloud_storage;
namespace fs = std::filesystem;

const std::string bucket_name = "secure-cloud-storage";

std::string settings_dir = default_settings_dir;

void list_files(std::ostream &out, const std::string &path) {
    for (auto &item: fs::directory_iterator(fs::path(path))) {
        out << item.path().filename().string() << (fs::is_directory(item) ? "/" : "") << std::endl;
    }
}

void insert_commands(ClientOperator<Tag> &co, const std::unique_ptr<cli::Menu> &rootMenu) {
    rootMenu->Insert(
            "ls",
            [&co](std::ostream &out) {
                const std::vector<std::string> files = co.list_files();
                if (files.empty()) {
                    out << "No files found." << std::endl;
                }
                for (auto &f: files) {
                    out << f << std::endl;
                }
            },
            "List files stored in the cloud");
    rootMenu->Insert(
            "read", // TODO cget, which writes file to desired location
            [&co](std::ostream &out, const std::string &path) {
                fs::path p(path);
                const std::vector<unsigned char> contents = co.get(co.get_id(path));
                out << std::string(contents.begin(), contents.end()) << std::endl;
            },
            "Get and print the file stored in the cloud under <path>",
            {"path"});

    rootMenu->Insert(
            "put",
            [&co](std::ostream &out, const std::string &local_path) {
                fs::path p(local_path);
                if (!exists(p)) {
                    out << "File in path " << local_path << " was not found.";
                }
                if (is_directory(p)) { // TODO as in ftp different command for multiple files/directories
                    out << "Found directory, uploading files." << std::endl;
                    for (auto &entry: fs::recursive_directory_iterator(p)) {
                        if (fs::is_regular_file(entry)) {
                            out << "Uploading file " << entry.path() << std::endl;
                            std::vector<unsigned char> content = FileUtil::read_file(entry.path());
                            co.put(entry, content);
                        }
                    }
                    out << "Done." << std::endl;
                } else {
                    std::vector<unsigned char> content = FileUtil::read_file(p);
                    co.put(p, content);
                }
            },
            "Load a file stored in <local_path> to the cloud",
            {"local_path"});

    rootMenu->Insert(
            "shred", // TODO version for directories, with prompt for confirmation
            [&co](std::ostream &out, const std::string &cloud_path) {
                // translate the path to the id
                Id<Tag> id = co.get_id(cloud_path);
                co.shred(id);
            },
            "Shred a file in the cloud",
            {"cloud_path"});

    rootMenu->Insert( // TODO failsafe: prompt for confirmation
            "clean",
            [&co](std::ostream &out) {
                out << "Cleaning the cloud: files without references are being deleted." << std::endl;
                out << "Number of deleted objects: " << co.clean() << std::endl;
            },
            "Remove files from the cloud which have no reference");

    rootMenu->Insert(
            "rotate-keys",
            [&co](std::ostream &out) {
                out << "Rekeying files." << std::endl;
                out << "Number of affected objects: " << co.rotate_keys(
                        std::make_shared<PPRF_AEAD_PKW>(co.get_tag_len(), co.get_key_len())) << std::endl;
            },
            "Generate a fresh secret key and rotate wrapped keys.");

    rootMenu->Insert(
            "lls",
            [](std::ostream &out) {
                list_files(out, ".");
            },
            "List local files");
    rootMenu->Insert(
            "lls",
            [](std::ostream &out, const std::string &path) {
                list_files(out, path);
            },
            "List local files at <path>",
            {"path"});
}

std::vector<unsigned char> getOrInitRatchetKey() {
    std::vector<unsigned char> ratchet_key(default_key_len / 8);
    try {
        ratchet_key = FileUtil::read_file(fs::path(settings_dir) / lookup_table_ratchet_key_filename);
    } catch (std::runtime_error &e) {
        CryptoPP::OS_GenerateRandomBlock(false, ratchet_key.data(), ratchet_key.size());
    }
    return ratchet_key;
}


std::map<std::string, std::string> read_tab_separated_map(const fs::path &properties_path) {
    std::ifstream properties_file_stream(properties_path, std::ios::in);
    std::map<std::string, std::string> properties;
    std::string line;
    while (std::getline(properties_file_stream, line)) {
        size_t pos = line.find('\t');
        std::string prop_name = line.substr(0, pos);
        std::string prop_val = line.substr(pos + 1, line.size());
        properties.insert(std::make_pair(prop_name, prop_val));
    }
    properties_file_stream.close();
    return properties;
}

ClientOperator<Tag> getClientOperatorFromSettings() {
    const fs::path settings(settings_dir);
    // check that settings directory, key file and mapping file exist
    const fs::path key_path = settings / key_filename;
    const fs::path properties_path = settings / properties_filename;
    if (fs::exists(settings) && fs::exists(key_path) && fs::exists(properties_path)) {
        std::ifstream key_file_stream(key_path, std::ios::in);
        // read key file and construct PKW object
        std::vector<unsigned char> file_buffer((std::istreambuf_iterator<char>(key_file_stream)),
                                               std::istreambuf_iterator<char>());
        key_file_stream.close();
        PPRF_AEAD_PKW_Factory factory;
        SecureByteBuffer key_file(file_buffer);
        auto pkw = factory.fromSerialized(key_file);

        // read lookup_table
        std::string enc_lookup_table;
        std::map<std::filesystem::path, Id<Tag>> lookup_table;
        try {
            enc_lookup_table = GCSCloudCommunicator<Tag>(bucket_name).read_lookup_table_from_cloud();
            auto table_vector = std::vector<unsigned char>({enc_lookup_table.begin(), enc_lookup_table.end()});
            auto table_buffer = SecureByteBuffer(table_vector);
            auto ratchet_key = getOrInitRatchetKey();
            SecureByteBuffer key_buffer(ratchet_key);
            SecureByteBuffer iv(16);
            auto dec_lookup_table = decrypt(table_buffer, key_buffer, iv, {0});
            auto lookup_table_stream = std::stringstream({dec_lookup_table.begin(), dec_lookup_table.end()});

            std::string line;
            while (std::getline(lookup_table_stream, line)) {
                size_t pos = line.find('\t');
                std::string p = line.substr(0, pos);
                size_t pos2 = line.find('\t', pos + 1);
                std::string localId = line.substr(pos + 1, pos2 - pos - 1);
                std::string remoteId = line.substr(pos2 + 1, line.size());
                Tag t(localId);
                Id<Tag> id(t, remoteId);
                lookup_table.insert(std::make_pair(p, id));
            }
        } catch (std::exception &e) {
            std::cout << "Could not find lookup table." << std::endl;
        }

        // ratchet forward lookup table key
        auto ratchet_key = getOrInitRatchetKey();
        CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
        std::vector<unsigned char> next_key(ratchet_key.size());
        std::vector<unsigned char> context = {'n'};
        hkdf.DeriveKey(next_key.data(), next_key.size(), ratchet_key.data(), ratchet_key.size(),
                       nullptr, 0, context.data(), context.size());
        FileUtil::write_file(next_key, true, fs::path(settings_dir) / lookup_table_ratchet_key_filename);

        // read properties
        std::map<std::string, std::string> properties = read_tab_separated_map(properties_path);
        int key_len = std::stoi(properties["key_len"]);
        int tag_len = std::stoi(properties["tag_len"]);

        // Use stored settings to initialize object
        return {pkw,
                std::make_shared<secure_cloud_storage::FlatIdProvider>(lookup_table, tag_len), tag_len, key_len,
                std::make_shared<secure_cloud_storage::GCSCloudCommunicator<Tag>>(bucket_name)};
    } else {
        // construct fresh object
        return {default_tag_len, default_key_len,
                std::make_unique<secure_cloud_storage::GCSCloudCommunicator<Tag>>(bucket_name),
                std::make_unique<FlatIdProvider>(default_tag_len),
                std::make_unique<PPRF_AEAD_PKW>(default_tag_len, default_key_len)};
    }
}

void store_key(ClientOperator<Tag> &co) {
    SecureByteBuffer key = co.export_key();
    std::ofstream key_file_stream(fs::path(settings_dir) / key_filename);
    key_file_stream << std::string(key.begin(), key.end());
    key_file_stream.close();
}

void store_lookup_table(ClientOperator<Tag> &co) {
    auto comm = GCSCloudCommunicator<Tag>(bucket_name);
    std::stringstream lookup_table_filestream;
    for (auto &filename: co.list_files()) {
        const Id<Tag> &id = co.get_id(filename);
        lookup_table_filestream << filename << "\t" << id.getLocalId() << "\t" << id.getRemoteId() << std::endl;
    }
    auto ratchet_key = getOrInitRatchetKey();
    auto table = lookup_table_filestream.str();
    auto table_vector = std::vector<unsigned char>({table.begin(), table.end()});
    auto table_buffer = SecureByteBuffer(table_vector);
    SecureByteBuffer key_buffer(ratchet_key);
    SecureByteBuffer iv(16);
    auto encrypted_lookup_table = encrypt(table_buffer, key_buffer, iv, {0});
    comm.write_lookup_table_to_cloud({encrypted_lookup_table.begin(), encrypted_lookup_table.end()});
}

void store_properties(ClientOperator<Tag> &co) {
    std::ofstream properties_filestream(fs::path(settings_dir) / properties_filename);
    properties_filestream << "key_len" << "\t" << co.get_key_len() << std::endl;
    properties_filestream << "tag_len" << "\t" << co.get_tag_len() << std::endl;
    properties_filestream.close();
}

int main(int argc, [[maybe_unused]] char *argv[]) {
    if (argc > 1) {
        // Look for settings at specified path
        settings_dir = argv[1];
    } else {
        // Look for settings at default path
        settings_dir = default_settings_dir;
    }

    ClientOperator<Tag> co = getClientOperatorFromSettings(); // TODO store/load pkw key with password
    auto rootMenu = std::make_unique<cli::Menu>("cli");
    insert_commands(co, rootMenu);

    cli::Cli cli(std::move(rootMenu));

    cli::LoopScheduler scheduler;
    // global exit action
    cli.ExitAction([&scheduler, &co](auto &out) {
        out << "Settings are stored at: " << settings_dir << std::endl;
        if (!fs::exists(settings_dir)) {
            fs::create_directory(settings_dir);
        }
        store_key(co);
        store_lookup_table(co);
        store_properties(co);
        scheduler.Stop();
    });
    cli::CliLocalTerminalSession input(cli, scheduler, std::cout);
    scheduler.Run();
    return 0;
}