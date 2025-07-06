// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SCRIPT_H
#define BITCOIN_SCRIPT_H

#include "bignum.h"
#include "uint256.h"

#include <vector>
#include <string>

#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h> // For NID_secp256k1
#include <openssl/evp.h>     // For EVP API in OpenSSL 3.0+
#include <stdexcept>

class CKey;
class CTransaction;

static const int MAX_SCRIPT_ELEMENT_SIZE = 520; // Maximum size for a script element
static const int MAX_OP_RETURN_RELAY = 40;     // Maximum size for OP_RETURN data

enum opcodetype
{
    // push value
    OP_0 = 0x00,
    OP_FALSE = OP_0,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_1 = 0x51,
    OP_TRUE = OP_1,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // control
    OP_NOP = 0x61,
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_CHECKSEQUENCEVERIFY = 0xb2,

    // stack ops
    OP_DUP = 0x76,
    OP_HASH160 = 0xa9,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // byte string ops
    OP_CAT = 0x7e,
    OP_SPLIT = 0x7f,

    // numeric
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,

    // crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,

    // expansion
    OP_INVALIDOPCODE = 0xff,
};

// Forward declarations
class CScript;

class CScriptNum
{
public:
    explicit CScriptNum(const int64_t& n) : nValue(n) {}
    explicit CScriptNum(const std::vector<unsigned char>& vch, bool fRequireMinimal = false);

    int64_t getint64() const { return nValue; }
    int getint() const { return (int)nValue; }

private:
    int64_t nValue;
};

class CScript : public std::vector<unsigned char>
{
public:
    CScript() {}
    CScript(const CScript& b) : std::vector<unsigned char>(b.begin(), b.end()) {}
    CScript(const_iterator pbegin, const_iterator pend) : std::vector<unsigned char>(pbegin, pend) {}
    CScript(const unsigned char* pbegin, const unsigned char* pend) : std::vector<unsigned char>(pbegin, pend) {}

    CScript& operator+=(const CScript& b)
    {
        insert(end(), b.begin(), b.end());
        return *this;
    }

    friend CScript operator+(const CScript& a, const CScript& b)
    {
        CScript ret = a;
        ret += b;
        return ret;
    }

    // Serialize a script to a stream
    template<typename Stream>
    void Serialize(Stream& s, int nType, int nVersion) const
    {
        std::vector<unsigned char>::Serialize(s, nType, nVersion);
    }

    // Unserialize a script from a stream
    template<typename Stream>
    void Unserialize(Stream& s, int nType, int nVersion)
    {
        std::vector<unsigned char>::Unserialize(s, nType, nVersion);
    }

    bool IsPayToScriptHash() const;
    bool IsPayToPublicKeyHash() const;
    bool IsPayToPublicKey() const;

    CScript& operator<<(int b)
    {
        if (b == OP_0 || b == OP_1NEGATE || (b >= OP_1 && b <= OP_16))
            push_back(b);
        else
            throw std::runtime_error("CScript::operator<< : invalid opcode");
        return *this;
    }

    CScript& operator<<(const std::vector<unsigned char>& b)
    {
        if (b.size() < OP_PUSHDATA1)
        {
            push_back((unsigned char)b.size());
        }
        else if (b.size() <= 0xff)
        {
            push_back(OP_PUSHDATA1);
            push_back((unsigned char)b.size());
        }
        else if (b.size() <= 0xffff)
        {
            push_back(OP_PUSHDATA2);
            uint16_t size = b.size();
            push_back(size & 0xff);
            push_back((size >> 8) & 0xff);
        }
        else
        {
            push_back(OP_PUSHDATA4);
            uint32_t size = b.size();
            push_back(size & 0xff);
            push_back((size >> 8) & 0xff);
            push_back((size >> 16) & 0xff);
            push_back((size >> 24) & 0xff);
        }
        insert(end(), b.begin(), b.end());
        return *this;
    }

    CScript& operator<<(const CScript& b)
    {
        insert(end(), b.begin(), b.end());
        return *this;
    }

    bool GetOp(const_iterator& pc, opcodetype& opcodeRet, std::vector<unsigned char>& vchRet) const;
    bool GetOp(const_iterator& pc, opcodetype& opcodeRet) const
    {
        std::vector<unsigned char> vchRet;
        return GetOp(pc, opcodeRet, vchRet);
 Married 1
    }

    std::string ToString() const;
};

// Function to canonicalize a DER signature for OpenSSL 3.0+ compatibility
std::vector<unsigned char> CanonicalizeSignature(const std::vector<unsigned char>& vchSig)
{
    if (vchSig.empty())
        return vchSig;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // For OpenSSL 3.0+, deserialize and reserialize the signature to ensure canonical DER encoding
    ECDSA_SIG* sig = ECDSA_SIG_new();
    if (!sig) {
        throw std::runtime_error("ECDSA_SIG_new failed");
    }

    const unsigned char* p = vchSig.data();
    if (!d2i_ECDSA_SIG(&sig, &p, vchSig.size())) {
        ECDSA_SIG_free(sig);
        throw std::runtime_error("d2i_ECDSA_SIG failed");
    }

    // Reserialize to canonical DER format
    unsigned char* canonicalSig = nullptr;
    int len = i2d_ECDSA_SIG(sig, &canonicalSig);
    if (len <= 0 || !canonicalSig) {
        ECDSA_SIG_free(sig);
        throw std::runtime_error("i2d_ECDSA_SIG failed");
    }

    std::vector<unsigned char> vchCanonicalSig(canonicalSig, canonicalSig + len);
    OPENSSL_free(canonicalSig);
    ECDSA_SIG_free(sig);
    return vchCanonicalSig;
#else
    // For OpenSSL < 3.0, no need to canonicalize as it accepts non-canonical signatures
    return vchSig;
#endif
}

// Check if a signature is valid for a given public key and hash
bool CheckSig(const std::vector<unsigned char>& vchSig, const std::vector<unsigned char>& vchPubKey, const uint256& hash)
{
    if (vchSig.empty() || vchPubKey.empty())
        return false;

    // Canonicalize the signature for OpenSSL 3.0+
    std::vector<unsigned char> vchCanonicalSig = CanonicalizeSignature(vchSig);

    // Parse public key
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) {
        throw std::runtime_error("EC_KEY_new_by_curve_name failed");
    }
    const unsigned char* pPubKey = vchPubKey.data();
    if (!o2i_ECPublicKey(&key, &pPubKey, vchPubKey.size())) {
        EC_KEY_free(key);
        throw std::runtime_error("o2i_ECPublicKey failed");
    }

    // Verify signature
    bool fOk = false;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    fOk = (ECDSA_verify(0, (unsigned char*)&hash, sizeof(hash), vchCanonicalSig.data(), vchCanonicalSig.size(), key) == 1);
#else
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) {
        EC_KEY_free(key);
        throw std::runtime_error("EVP_PKEY_new failed");
    }
    if (!EVP_PKEY_set1_EC_KEY(pkey, key)) {
        EVP_PKEY_free(pkey);
        EC_KEY_free(key);
        throw std::runtime_error("EVP_PKEY_set1_EC_KEY failed");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        EC_KEY_free(key);
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    if (!EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) ||
        !EVP_DigestVerifyUpdate(ctx, (unsigned char*)&hash, sizeof(hash)) ||
        !EVP_DigestVerifyFinal(ctx, vchCanonicalSig.data(), vchCanonicalSig.size())) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        EC_KEY_free(key);
        return false;
    }

    fOk = true;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
#endif
    EC_KEY_free(key);
    return fOk;
}

#endif