// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_HASH_H
#define BITCOIN_HASH_H

#include "uint256.h"
#include "serialize.h"

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/evp.h> // Added for EVP API
#include <stdexcept>    // Added for error handling
#include <vector>

template<typename T1>
inline uint256 Hash(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint256 hash1;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    SHA256((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
#else
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
        !EVP_DigestUpdate(ctx, (pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0])) ||
        !EVP_DigestFinal_ex(ctx, (unsigned char*)&hash1, NULL)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_Digest failed");
    }
    EVP_MD_CTX_free(ctx);
#endif
    uint256 hash2;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
#else
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
        !EVP_DigestUpdate(ctx, (unsigned char*)&hash1, sizeof(hash1)) ||
        !EVP_DigestFinal_ex(ctx, (unsigned char*)&hash2, NULL)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_Digest failed");
    }
    EVP_MD_CTX_free(ctx);
#endif
    return hash2;
}

class CHashWriter
{
private:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    SHA256_CTX ctx;
#else
    EVP_MD_CTX* ctx;
#endif
public:
    int nType;
    int nVersion;

    CHashWriter(int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        ctx = EVP_MD_CTX_new();
        if (!ctx) {
            throw std::runtime_error("EVP_MD_CTX_new failed");
        }
#endif
        Init();
    }

    ~CHashWriter() {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        EVP_MD_CTX_free(ctx);
#endif
    }

    void Init() {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
        if (!SHA256_Init(&ctx)) {
            throw std::runtime_error("SHA256_Init failed");
        }
#else
        if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
            throw std::runtime_error("EVP_DigestInit_ex failed");
        }
#endif
    }

    CHashWriter& write(const char *pch, size_t size) {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
        if (!SHA256_Update(&ctx, pch, size)) {
            throw std::runtime_error("SHA256_Update failed");
        }
#else
        if (!EVP_DigestUpdate(ctx, pch, size)) {
            throw std::runtime_error("EVP_DigestUpdate failed");
        }
#endif
        return *this;
    }

    // Invalidates the object
    uint256 GetHash() {
        uint256 hash1;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
        if (!SHA256_Final((unsigned char*)&hash1, &ctx)) {
            throw std::runtime_error("SHA256_Final failed");
        }
#else
        if (!EVP_DigestFinal_ex(ctx, (unsigned char*)&hash1, NULL)) {
            throw std::runtime_error("EVP_DigestFinal_ex failed");
        }
#endif
        uint256 hash2;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
        SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
#else
        EVP_MD_CTX* temp_ctx = EVP_MD_CTX_new();
        if (!temp_ctx) {
            throw std::runtime_error("EVP_MD_CTX_new failed");
        }
        if (!EVP_DigestInit_ex(temp_ctx, EVP_sha256(), NULL) ||
            !EVP_DigestUpdate(temp_ctx, (unsigned char*)&hash1, sizeof(hash1)) ||
            !EVP_DigestFinal_ex(temp_ctx, (unsigned char*)&hash2, NULL)) {
            EVP_MD_CTX_free(temp_ctx);
            throw std::runtime_error("EVP_Digest failed");
        }
        EVP_MD_CTX_free(temp_ctx);
#endif
        return hash2;
    }

    template<typename T>
    CHashWriter& operator<<(const T& obj) {
        // Serialize to this stream
        ::Serialize(*this, obj, nType, nVersion);
        return *this;
    }
};

template<typename T1, typename T2>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end)
{
    static unsigned char pblank[1];
    uint256 hash1;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    SHA256_CTX ctx;
    if (!SHA256_Init(&ctx)) {
        throw std::runtime_error("SHA256_Init failed");
    }
    if (!SHA256_Update(&ctx, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0])) ||
        !SHA256_Update(&ctx, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0])) ||
        !SHA256_Final((unsigned char*)&hash1, &ctx)) {
        throw std::runtime_error("SHA256 failed");
    }
#else
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
        !EVP_DigestUpdate(ctx, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0])) ||
        !EVP_DigestUpdate(ctx, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0])) ||
        !EVP_DigestFinal_ex(ctx, (unsigned char*)&hash1, NULL)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_Digest failed");
    }
    EVP_MD_CTX_free(ctx);
#endif
    uint256 hash2;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
#else
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
        !EVP_DigestUpdate(ctx, (unsigned char*)&hash1, sizeof(hash1)) ||
        !EVP_DigestFinal_ex(ctx, (unsigned char*)&hash2, NULL)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_Digest failed");
    }
    EVP_MD_CTX_free(ctx);
#endif
    return hash2;
}

template<typename T1, typename T2, typename T3>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end,
                    const T3 p3begin, const T3 p3end)
{
    static unsigned char pblank[1];
    uint256 hash1;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    SHA256_CTX ctx;
    if (!SHA256_Init(&ctx)) {
        throw std::runtime_error("SHA256_Init failed");
    }
    if (!SHA256_Update(&ctx, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0])) ||
        !SHA256_Update(&ctx, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0])) ||
        !SHA256_Update(&ctx, (p3begin == p3end ? pblank : (unsigned char*)&p3begin[0]), (p3end - p3begin) * sizeof(p3begin[0])) ||
        !SHA256_Final((unsigned char*)&hash1, &ctx)) {
        throw std::runtime_error("SHA256 failed");
    }
#else
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
        !EVP_DigestUpdate(ctx, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0])) ||
        !EVP_DigestUpdate(ctx, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0])) ||
        !EVP_DigestUpdate(ctx, (p3begin == p3end ? pblank : (unsigned char*)&p3begin[0]), (p3end - p3begin) * sizeof(p3begin[0])) ||
        !EVP_DigestFinal_ex(ctx, (unsigned char*)&hash1, NULL)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_Digest failed");
    }
    EVP_MD_CTX_free(ctx);
#endif
    uint256 hash2;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
#else
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
        !EVP_DigestUpdate(ctx, (unsigned char*)&hash1, sizeof(hash1)) ||
        !EVP_DigestFinal_ex(ctx, (unsigned char*)&hash2, NULL)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_Digest failed");
    }
    EVP_MD_CTX_free(ctx);
#endif
    return hash2;
}

template<typename T>
uint256 SerializeHash(const T& obj, int nType=SER_GETHASH, int nVersion=PROTOCOL_VERSION)
{
    CHashWriter ss(nType, nVersion);
    ss << obj;
    return ss.GetHash();
}

inline uint160 Hash160(const std::vector<unsigned char>& vch)
{
    uint256 hash1;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    SHA256(&vch[0], vch.size(), (unsigned char*)&hash1);
#else
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
        !EVP_DigestUpdate(ctx, &vch[0], vch.size()) ||
        !EVP_DigestFinal_ex(ctx, (unsigned char*)&hash1, NULL)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_Digest failed");
    }
    EVP_MD_CTX_free(ctx);
#endif
    uint160 hash2;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (!RIPEMD160((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2)) {
        throw std::runtime_error("RIPEMD160 failed");
    }
#else
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    if (!EVP_DigestInit_ex(ctx, EVP_ripemd160(), NULL) ||
        !EVP_DigestUpdate(ctx, (unsigned char*)&hash1, sizeof(hash1)) ||
        !EVP_DigestFinal_ex(ctx, (unsigned char*)&hash2, NULL)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_Digest failed");
    }
    EVP_MD_CTX_free(ctx);
#endif
    return hash2;
}

unsigned int MurmurHash3(unsigned int nHashSeed, const std::vector<unsigned char>& vDataToHash);

#endif
