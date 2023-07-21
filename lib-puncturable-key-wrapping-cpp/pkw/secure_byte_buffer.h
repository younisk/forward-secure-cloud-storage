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

#ifndef PUNCTURABLE_KEY_WRAPPING_CPP_SECURE_BYTE_BUFFER_H
#define PUNCTURABLE_KEY_WRAPPING_CPP_SECURE_BYTE_BUFFER_H
#include <cstddef>
#include <vector>

/**
 * A byte buffer which erases the memory it occupies before it is destructed.
 * The interface resembles that of a std::vector<unsigned char>.
 */
class SecureByteBuffer {
    public:
        SecureByteBuffer() = default;
        explicit SecureByteBuffer(size_t n) : vec(n) {}
        SecureByteBuffer(const SecureByteBuffer &buff) noexcept;
        SecureByteBuffer(SecureByteBuffer &&buff) noexcept;
        /**
         * Move operator
         */
        SecureByteBuffer &operator=(SecureByteBuffer &&rhs) noexcept;

        /**
         *Copy operator
         **/
        SecureByteBuffer &operator=(const SecureByteBuffer &rhs) noexcept;

        /**
         * Constructor which swaps the memory of the passed vector into the secure buffer.
         * @param vec the vector
         */
        explicit SecureByteBuffer(std::vector<unsigned char> &vec);
        bool operator==(const SecureByteBuffer &rhs) const;
        bool operator!=(const SecureByteBuffer &rhs) const;
        SecureByteBuffer(unsigned long n, const unsigned char &x) : vec(n, x) {}
        virtual ~SecureByteBuffer();
        unsigned char *data();
        const unsigned char *data() const;
        size_t size() const;

        using container = std::vector<unsigned char>;
        using iterator = typename container::iterator;
        using const_iterator = typename container::const_iterator;

        iterator begin() { return vec.begin(); }
        iterator end() { return vec.end(); }
        const_iterator begin() const { return vec.begin(); }
        const_iterator end() const { return vec.end(); }


    private:
        friend class PPRFKeySerializer;
        std::vector<unsigned char> vec;
};
#endif//PUNCTURABLE_KEY_WRAPPING_CPP_SECURE_BYTE_BUFFER_H