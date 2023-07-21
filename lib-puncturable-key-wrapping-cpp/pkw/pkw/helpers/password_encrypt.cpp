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

#include "password_encrypt.h"
#include "../exceptions.h"
#include <cryptopp/aes.h>
#include <cryptopp/channels.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <vector>

#define MAC_LEN 12
#define NONCE_LEN 16
#define KEY_LEN 16
#define SALT_LEN 16
#define ITERS 100

SecureByteBuffer generateKeyFromPassword(const std::string &password, SecureByteBuffer &salt);

SecureByteBuffer encryptExport(SecureByteBuffer &plaintext, const std::string &password) {
    SecureByteBuffer salt(SALT_LEN);
    CryptoPP::OS_GenerateRandomBlock(true, salt.data(), salt.size());
    SecureByteBuffer enc_key = generateKeyFromPassword(password, salt);

    SecureByteBuffer iv(NONCE_LEN);
    CryptoPP::OS_GenerateRandomBlock(false, iv.data(), iv.size());

    std::vector<unsigned char> ciphertext = encrypt(plaintext, enc_key, iv, std::vector<unsigned char>());

    ciphertext.insert(ciphertext.end(), iv.begin(), iv.end());
    ciphertext.insert(ciphertext.end(), salt.begin(), salt.end());
    return SecureByteBuffer(ciphertext);
}

std::vector<unsigned char> encrypt(SecureByteBuffer &plaintext, SecureByteBuffer &enc_key, SecureByteBuffer &iv, std::vector<unsigned char> aad) {
    CryptoPP::GCM<CryptoPP::AES>::Encryption e;
    std::vector<unsigned char> ciphertext;
    e.SetKeyWithIV(enc_key.data(), enc_key.size(), iv.data(), iv.size());
    CryptoPP::AuthenticatedEncryptionFilter ef(e,
                                               new CryptoPP::VectorSink(ciphertext), false,
                                               MAC_LEN /* MAC_AT_END */);
    ef.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
    ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);

    // Confidential data comes after authenticated data.
    // This is a limitation due to CCM mode, not GCM mode.
    ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, plaintext.data(), plaintext.size());
    ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
    return ciphertext;
}
SecureByteBuffer generateKeyFromPassword(const std::string &password, SecureByteBuffer &salt) {
    SecureByteBuffer enc_key(KEY_LEN);
    CryptoPP::PKCS12_PBKDF<CryptoPP::SHA256> kdf;
    if (kdf.DeriveKey(enc_key.data(), enc_key.size(), 0, reinterpret_cast<const CryptoPP::byte *>(password.c_str()), password.size(), salt.data(), salt.size(),
                      ITERS, 0) != ITERS) {
        throw ExportException();
    }
    return enc_key;
}

SecureByteBuffer decryptExport(const SecureByteBuffer &data, const std::string &password) {
    SecureByteBuffer salt(SALT_LEN);
    SecureByteBuffer iv(NONCE_LEN);

    /* get salt and nonce from end of ciphertext
         * format is: ciphertext || iv || salt    */
    copy(data.end() - salt.size(), data.end(), salt.begin());
    copy(data.end() - salt.size() - iv.size(), data.end() - salt.size(), iv.begin());

    SecureByteBuffer enc_key = generateKeyFromPassword(password, salt);
    std::vector<unsigned char> ciphertext(data.begin(), data.end() - salt.size() - iv.size());
    return decrypt(SecureByteBuffer(ciphertext), enc_key, iv, std::vector<unsigned char>());
}

SecureByteBuffer decrypt(const SecureByteBuffer &ciphertext, SecureByteBuffer &enc_key, SecureByteBuffer &iv, std::vector<unsigned char> aad) {
    try {
        CryptoPP::GCM<CryptoPP::AES>::Decryption d;
        d.SetKeyWithIV(enc_key.data(), enc_key.size(), iv.data(), iv.size());
        std::vector<unsigned char> enc(ciphertext.begin(), ciphertext.end() - MAC_LEN);
        std::vector<unsigned char> mac(ciphertext.end() - MAC_LEN, ciphertext.end());
        CryptoPP::AuthenticatedDecryptionFilter df(d,
                                                   nullptr, CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_BEGIN | CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                                                   MAC_LEN /* MAC_AT_END */);
        // The order of the following calls are important
        df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, mac.data(), mac.size());
        df.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
        df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, enc.data(), enc.size());

        // If the object throws, it will most likely occur
        //   during ChannelMessageEnd()
        df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
        df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        if (!df.GetLastResult()) {
            throw UnwrappingException();
        }

        // Remove data from channel
        std::vector<unsigned char> retrieved;

        // Plain text recovered from enc.data()
        df.SetRetrievalChannel(CryptoPP::DEFAULT_CHANNEL);
        size_t n = (size_t) df.MaxRetrievable();
        retrieved.resize(n);

        if (n > 0) {
            df.Get((unsigned char *) retrieved.data(), n);
        }
        return SecureByteBuffer(retrieved);
    } catch (CryptoPP::Exception &e) {
        throw ImportException();
    }
}