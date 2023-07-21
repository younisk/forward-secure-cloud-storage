/***********************************************************************************************************************
 * Copyright 2022 Younis Khalil
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *
 **********************************************************************************************************************/

#include "ggm_hpprf.h"
#include "pprf_exceptions.h"
#include "pprf_key_serializer.h"
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <deque>

static const std::vector<unsigned char> RIGHT({'r'});
static const std::vector<unsigned char> LEFT({'l'});
static const std::vector<unsigned char> OUT({'o'});

GGM_HPPRF::GGM_HPPRF(PPRFKey key) : key(std::move(key)) {
}

SecureByteBuffer GGM_HPPRF::eval(Tag tag) {
    std::string nodePrefix = findMatchingPrefix(tag);
    SecretRoot &node = key.nodes[nodePrefix];

    CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
    SecureByteBuffer res(node.getValue());
    SecureByteBuffer derived(res);
    for (size_t i = node.getPrefix().size(); i < tag.size(); i++) {
        const std::vector<unsigned char> &direction = tag[i] ? RIGHT : LEFT;
        hkdf.DeriveKey(derived.data(), derived.size(), res.data(), res.size(), nullptr, 0, direction.data(),
                       direction.size());
        res = derived;
    }
//    Before output of the value, we need to derive one more time, so as not to leak internal GGM state
    hkdf.DeriveKey(derived.data(), derived.size(), res.data(), res.size(), nullptr, 0, OUT.data(),
                   OUT.size());
    res = derived;
    return res;
}

std::string GGM_HPPRF::findMatchingPrefix(const Tag &tag) {
    std::string tagString = tag_to_string(tag);
    for (int i = 0; i <= tagString.size(); ++i) {
        std::string prefix = tagString.substr(0, i);
        if (key.nodes.count(prefix) > 0) {
            return prefix;
        }
    }
    throw TagException();
}

void GGM_HPPRF::punc(const Tag &tag) {
    std::string nodeIndex;
    try {
        nodeIndex = findMatchingPrefix(tag);
    } catch (TagException &t) {
        /* Could be hierarchichal puncture: remove all nodes from key with tag as prefix */
        auto tag_string = tag_to_string(tag);
        std::erase_if(key.nodes, [&tag_string](const auto &item) {
            return item.first.starts_with(tag_string);
        });
        return; /* already punctured */
    }

    SecretRoot &node = key.nodes[nodeIndex];
    key.puncs += 1;
    std::vector<SecretRoot> coPath;
    evalAndGetCoPath(tag, node, coPath);
    key.nodes.erase(nodeIndex);
    for (auto &n: coPath) {
        key.nodes.insert({n.getPrefix(), {n.getPrefix(), n.getValue()}});
    }
}

SecureByteBuffer
GGM_HPPRF::evalAndGetCoPath(const Tag &tag, const SecretRoot &node, std::vector<SecretRoot> &coPath) const {
    const int keyLenByte = key.keyLen / 8;
    CryptoPP::HKDF<CryptoPP::SHA256> hkdf;

    std::deque<SecretRoot> left;
    std::deque<SecretRoot> right;

    SecureByteBuffer curr(node.getValue());
    SecureByteBuffer derived_right(keyLenByte);
    SecureByteBuffer derived_left(keyLenByte);
    std::string pref = node.getPrefix();
    for (size_t i = node.getPrefix().size(); i < tag.size(); i++) {
        hkdf.DeriveKey(derived_right.data(), derived_right.size(), curr.data(), curr.size(), nullptr, 0, RIGHT.data(),
                       RIGHT.size());
        hkdf.DeriveKey(derived_left.data(), derived_left.size(), curr.data(), curr.size(), nullptr, 0, LEFT.data(),
                       LEFT.size());
        if (tag[i]) {
            left.emplace_back(pref + "0", derived_left);
            curr = derived_right;
            pref += "1";
        } else {
            right.emplace_front(pref + "1", derived_right);
            curr = derived_left;
            pref += "0";
        }
    }
    coPath.insert(coPath.end(), left.begin(), left.end());
    coPath.insert(coPath.end(), right.begin(), right.end());
    return curr;
}

int GGM_HPPRF::getNumPuncs() {
    return key.puncs;
}

int GGM_HPPRF::tagLen() {
    return key.tagLen;
}

SecureByteBuffer GGM_HPPRF::serializeKey() {
    return key.serialize();
}

std::string GGM_HPPRF::tag_to_string(const Tag &tag) {
    std::string ret;
    ret.reserve(tag.size());
    for (auto i: tag) {
        ret.append(i ? "1" : "0");
    }
    return ret;
}