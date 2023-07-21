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

#ifndef PUNCTURABLE_KEY_WRAPPING_CPP_SECRET_ROOT_H
#define PUNCTURABLE_KEY_WRAPPING_CPP_SECRET_ROOT_H

#include "../secure_byte_buffer.h"
#include <string>
/**
 * An element of a GGM Tree.
 * A SecretRoot contains a prefix and a value. The prefix denotes the the path taken from the original root of the tree to arrive at this root (of a subtree).
 * Uses a SecureBuffer which erases its contents on deconstruction.
 */
class SecretRoot {
    public:
        /**
         * Constructs a SecretRoot based on a (bit-string) prefix and a value.
         *
         * Example: prefix is "110101100", then the value allows for evaluation of tags starting with "110101100"
         * @param prefix the prefix as a bit-string
         * @param value the value, stored inside a SecureByteBuffer
         */
        SecretRoot(std::string prefix, SecureByteBuffer value);

        /**
         * Constructs an empty SecretRoot
         */
        SecretRoot();
        virtual ~SecretRoot() = default;

        /**
         * Getter for the prefix
         * @return the prefix
         */
        std::string getPrefix() const;

        /**
         * Getter for the value
         * @return the value
         */
        SecureByteBuffer getValue() const;


    private:
        std::string prefix;
        SecureByteBuffer value;
};
#endif//PUNCTURABLE_KEY_WRAPPING_CPP_SECRET_ROOT_H