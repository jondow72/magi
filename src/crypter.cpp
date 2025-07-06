// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/kdf.h> // For EVP_KDF in OpenSSL 3.0+
#include <vector>
#include <string>
#ifdef WIN32
#include <windows.h>
#endif

#include "crypter.h"

bool CCrypter::SetKeyFromPassphrase(const SecureString& strKeyData, const std::vector<unsigned char>& chSalt, const unsigned int nRounds, const unsigned int nDerivationMethod)
{
    if (nRounds < 1 || chSalt.size() != WALLET_CRYPTO_SALT_SIZE)
        return false;

    int i = 0;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), &chSalt[0],
                       (unsigned char *)&strKeyData[0], strKeyData.size(), nRounds, chKey, chIV);
#else
    EVP_KDF* kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    if (!kdf) {
        return false;
    }
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) {
        return false;
    }
    unsigned char derived[WALLET_CRYPTO_KEY_SIZE + WALLET_CRYPTO_KEY_SIZE];
    size_t derived_len = sizeof(derived);
    if (EVP_KDF_CTX_set_kdf_pbkdf2_rounds(kctx, nRounds) <= 0 ||
        EVP_KDF_CTX_set_kdf_pbkdf2_salt(kctx, &chSalt[0], chSalt.size()) <= 0 ||
        EVP_KDF_derive(kctx, derived, derived_len, EVP_sha512()) <= 0) {
        EVP_KDF_CTX_free(kctx);
        return false;
    }
    EVP_KDF_CTX_free(kctx);
    memcpy(chKey, derived, WALLET_CRYPTO_KEY_SIZE);
    memcpy(chIV, derived + WALLET_CRYPTO_KEY_SIZE, WALLET_CRYPTO_KEY_SIZE);
    i = WALLET_CRYPTO_KEY_SIZE;
#endif

    if (i != (int)WALLET_CRYPTO_KEY_SIZE)
    {
        memset(&chKey, 0, sizeof chKey);
        memset(&chIV, 0, sizeof chIV);
        return false;
    }

    fKeySet = true;
    return true;
}

bool CCrypter::SetKey(const CKeyingMaterial& chNewKey, const std::vector<unsigned char>& chNewIV)
{
    if (chNewKey.size() != WALLET_CRYPTO_KEY_SIZE || chNewIV.size() != WALLET_CRYPTO_KEY_SIZE)
        return false;

    memcpy(&chKey[0], &chNewKey[0], sizeof chKey);
    memcpy(&chIV[0], &chNewIV[0], sizeof chIV);

    fKeySet = true;
    return true;
}

bool CCrypter::Encrypt(const CKeyingMaterial& vchPlaintext, std::vector<unsigned char> &vchCiphertext)
{
    if (!fKeySet)
        return false;

    int nLen = vchPlaintext.size();
    int nCLen = nLen + AES_BLOCK_SIZE, nFLen = 0;
    vchCiphertext = std::vector<unsigned char> (nCLen);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
#else
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }
#endif

    bool fOk = true;

    if (fOk) fOk = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, chKey, chIV);
    if (fOk) fOk = EVP_EncryptUpdate(ctx, &vchCiphertext[0], &nCLen, &vchPlaintext[0], nLen);
    if (fOk) fOk = EVP_EncryptFinal_ex(ctx, (&vchCiphertext[0])+nCLen, &nFLen);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    EVP_CIPHER_CTX_cleanup(&ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif

    if (!fOk) return false;

    vchCiphertext.resize(nCLen + nFLen);
    return true;
}

bool CCrypter::Decrypt(const std::vector<unsigned char>& vchCiphertext, CKeyingMaterial& vchPlaintext)
{
    if (!fKeySet)
        return false;

    int nLen = vchCiphertext.size();
    int nPLen = nLen, nFLen = 0;

    vchPlaintext = CKeyingMaterial(nPLen);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
#else
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }
#endif

    bool fOk = true;

    if (fOk) fOk = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, chKey, chIV);
    if (fOk) fOk = EVP_DecryptUpdate(ctx, &vchPlaintext[0], &nPLen, &vchCiphertext[0], nLen);
    if (fOk) fOk = EVP_DecryptFinal_ex(ctx, (&vchPlaintext[0])+nPLen, &nFLen);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    EVP_CIPHER_CTX_cleanup(&ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif

    if (!fOk) return false;

    vchPlaintext.resize(nPLen + nFLen);
    return true;
}

bool EncryptSecret(CKeyingMaterial& vMasterKey, const CSecret &vchPlaintext, const uint256& nIV, std::vector<unsigned char> &vchCiphertext)
{
    CCrypter cKeyCrypter;
    std::vector<unsigned char> chIV(WALLET_CRYPTO_KEY_SIZE);
    memcpy(&chIV[0], &nIV, WALLET_CRYPTO_KEY_SIZE);
    if(!cKeyCrypter.SetKey(vMasterKey, chIV))
        return false;
    return cKeyCrypter.Encrypt((CKeyingMaterial)vchPlaintext, vchCiphertext);
}

bool DecryptSecret(const CKeyingMaterial& vMasterKey, const std::vector<unsigned char>& vchCiphertext, const uint256& nIV, CSecret& vchPlaintext)
{
    CCrypter cKeyCrypter;
    std::vector<unsigned char> chIV(WALLET_CRYPTO_KEY_SIZE);
    memcpy(&chIV[0], &nIV, WALLET_CRYPTO_KEY_SIZE);
    if(!cKeyCrypter.SetKey(vMasterKey, chIV))
        return false;
    return cKeyCrypter.Decrypt(vchCiphertext, *((CKeyingMaterial*)&vchPlaintext));
}