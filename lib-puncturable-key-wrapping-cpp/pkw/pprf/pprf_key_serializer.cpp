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

#include "pprf_key_serializer.h"
#include "pprf_exceptions.h"
#include "secret_root.h"
#include <arpa/inet.h>

SecureByteBuffer PPRFKeySerializer::serialize() {
    SecureByteBuffer buffer = SecureByteBuffer();
    std::vector<unsigned char> &underlyingBuffer = buffer.vec;
    writeInteger(underlyingBuffer, keyToSerialize.tagLen);
    writeInteger(underlyingBuffer, keyToSerialize.keyLen);
    writeInteger(underlyingBuffer, keyToSerialize.puncs);
    writeInteger(underlyingBuffer, keyToSerialize.nodes.size());
    for (auto &node: keyToSerialize.nodes) {
        writeNode(underlyingBuffer, node.second);
    }
    return buffer;
}

PPRFKey PPRFKeySerializer::deserialize(SecureByteBuffer &serialized) {
    size_t offset = 0;
    int tagLen = getInt(serialized, offset);
    offset += sizeof(uint64_t);
    int keyLen = getInt(serialized, offset);
    offset += sizeof(uint64_t);
    int puncs = getInt(serialized, offset);
    offset += sizeof(uint64_t);
    size_t numNodes = getSize(serialized, offset);
    offset += sizeof(uint64_t);
    std::unordered_map<std::string, SecretRoot> nodes;
    for (int i = 0; i < numNodes; ++i) {
        size_t stringSize = getSize(serialized, offset);
        offset += sizeof(size_t);
        std::string prefix = getString(serialized, offset, stringSize);
        offset += stringSize;
        int keyBytes = keyLen / 8;
        SecureByteBuffer value = copyValue(serialized, offset, keyBytes);
        offset += keyBytes;
        nodes.insert({prefix, {prefix, value}});
    }
    if (offset != serialized.size()) {
        throw PPRFDeserializationError();
    }
    return {keyLen, tagLen, puncs, nodes};
}


void PPRFKeySerializer::writeNode(std::vector<unsigned char> &buffer, const SecretRoot &node) {
    writeInteger(buffer, node.getPrefix().size());
    copy(buffer, (unsigned char *) node.getPrefix().c_str(), node.getPrefix().size());
    copy(buffer, node.getValue().data(), node.getValue().size());
}
void PPRFKeySerializer::copy(std::vector<unsigned char> &buffer, const unsigned char *toCopy, size_t size) {
    for (int i = 0; i < size; ++i) {
        buffer.push_back(toCopy[i] & 0xFF);
    }
}

void PPRFKeySerializer::writeInteger(std::vector<unsigned char> &underlyingBuffer, uint64_t t1) {
    uint64_t t2 = htonll(t1);
    for (int i = 0; i < sizeof(uint64_t); ++i) {
        unsigned char byte = (t2 >> (8 * i)) & 0xFF;
        underlyingBuffer.push_back(byte);
    }
}


int PPRFKeySerializer::getInt(SecureByteBuffer b, size_t offset) {
    uint64_t ret = getUInt64(b, offset);
    return ntohll(ret);
}
size_t PPRFKeySerializer::getSize(SecureByteBuffer b, size_t offset) {
    uint64_t ret = getUInt64(b, offset);
    return ntohll(ret);
}
size_t PPRFKeySerializer::getUInt64(SecureByteBuffer &b, size_t offset) {
    if (b.size() < offset + sizeof(uint64_t)) {
        throw PPRFDeserializationError();
    }
    uint64_t ret = 0;
    for (int i = 0; i < sizeof(uint64_t); i++) {
        uint64_t byte = b.data()[offset + i];
        ret = ret | (byte << (i * 8));
    }
    return ret;
}
std::string PPRFKeySerializer::getString(SecureByteBuffer b, size_t offset, size_t length) {
    if (b.size() < offset + length) {
        throw PPRFDeserializationError();
    }
    return {b.vec.begin() + offset, b.vec.begin() + offset + length};
}
SecureByteBuffer PPRFKeySerializer::copyValue(SecureByteBuffer from, size_t offset, size_t length) {
    if (from.size() < offset + length) {
        throw PPRFDeserializationError();
    }
    std::vector<unsigned char> res(from.vec.begin() + offset, from.vec.begin() + offset + length);
    return SecureByteBuffer(res);
}