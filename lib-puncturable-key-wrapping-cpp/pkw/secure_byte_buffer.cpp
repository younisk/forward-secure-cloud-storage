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

#include "secure_byte_buffer.h"
#include "secure_memzero.h"

SecureByteBuffer::~SecureByteBuffer() {
    secure_memzero(vec.data(), vec.size());
}
unsigned char *SecureByteBuffer::data() {
    return vec.data();
}

const unsigned char *SecureByteBuffer::data() const {
    return vec.data();
}

size_t SecureByteBuffer::size() const {
    return vec.size();
}

SecureByteBuffer::SecureByteBuffer(const SecureByteBuffer &buff) noexcept : vec(buff.vec) {
}
SecureByteBuffer::SecureByteBuffer(SecureByteBuffer &&buff) noexcept : vec(buff.vec) {
}


SecureByteBuffer &SecureByteBuffer::operator=(SecureByteBuffer &&rhs) noexcept {
    if (vec != rhs.vec) {
        secure_memzero(vec.data(), vec.size());
        vec.clear();
        vec = rhs.vec;
    }
    return *this;
}
bool SecureByteBuffer::operator==(const SecureByteBuffer &rhs) const {
    return vec == rhs.vec;
}
bool SecureByteBuffer::operator!=(const SecureByteBuffer &rhs) const {
    return !(vec == rhs.vec);
}
SecureByteBuffer::SecureByteBuffer(std::vector<unsigned char> &vec) : vec(0) {
    this->vec.swap(vec);
}

SecureByteBuffer &SecureByteBuffer::operator=(const SecureByteBuffer &rhs) noexcept = default;