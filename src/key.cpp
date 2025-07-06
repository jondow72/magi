// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <map>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "key.h"

// Generate a private key from just the secret parameter
int EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    EC_POINT *pub_key = NULL;
    EC_GROUP *group = NULL;

    if (!eckey) return 0;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) goto err;
#else
    group = const_cast<EC_GROUP*>(EC_KEY_get0_group(eckey));
    if (!group) goto err;
#endif

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    pub_key = EC_POINT_new(group);
    if (pub_key == NULL)
        goto err;

    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
        goto err;

    if (!EC_KEY_set_private_key(eckey, priv_key))
        goto err;
    if (!EC_KEY_set_public_key(eckey, pub_key))
        goto err;

    ok = 1;

err:
    if (pub_key)
        EC_POINT_free(pub_key);
    if (ctx != NULL)
        BN_CTX_free(ctx);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (group)
        EC_GROUP_free(group);
#endif
    return ok;
}

// Perform ECDSA key recovery for curves over (mod p)-fields
int ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig, const unsigned char *msg, int msglen, int recid, int check)
{
    if (!eckey) return 0;

    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *x = NULL;
    BIGNUM *e = NULL;
    BIGNUM *order = NULL;
    BIGNUM *sor = NULL;
    BIGNUM *eor = NULL;
    BIGNUM *field = NULL;
    EC_POINT *R = NULL;
    EC_POINT *O = NULL;
    EC_POINT *Q = NULL;
    BIGNUM *rr = NULL;
    BIGNUM *zero = NULL;
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    int n = 0;
    int i = recid / 2;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) { ret = -2; goto err; }
#else
    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    if (!group) { ret = -2; goto err; }
#endif

    if ((ctx = BN_CTX_new()) == NULL) { ret = -1; goto err; }
    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    if (!EC_GROUP_get_order(group, order, ctx)) { ret = -2; goto err; }
    x = BN_CTX_get(ctx);
    if (!BN_copy(x, order)) { ret = -1; goto err; }
    if (!BN_mul_word(x, i)) { ret = -1; goto err; }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    r = ECDSA_SIG_get0_r(ecsig);
    s = ECDSA_SIG_get0_s(ecsig);
#else
    ECDSA_SIG_get0(ecsig, &r, &s);
#endif
    if (!BN_add(x, x, r)) { ret = -1; goto err; }
    field = BN_CTX_get(ctx);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (!EC_GROUP_get_curve(group, field, NULL, NULL, ctx)) { ret = -2; goto err; }
#else
    if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx)) { ret = -2; goto err; }
#endif
    if (BN_cmp(x, field) >= 0) { ret = 0; goto err; }
    if ((R = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (!EC_POINT_set_compressed_coordinates(group, R, x, recid % 2, ctx)) { ret = 0; goto err; }
#else
    if (!EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)) { ret = 0; goto err; }
#endif
    if (check)
    {
        if ((O = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
        if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) { ret = -2; goto err; }
        if (!EC_POINT_is_at_infinity(group, O)) { ret = 0; goto err; }
    }
    if ((Q = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    n = EC_GROUP_get_degree(group);
    e = BN_CTX_get(ctx);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    if (!BN_lebin2bn(msg, msglen, e)) { ret = -1; goto err; }
#else
    if (!BN_bin2bn(msg, msglen, e)) { ret = -1; goto err; }
#endif
    if (8 * msglen > n) BN_rshift(e, e, 8 - (n & 7));
    zero = BN_CTX_get(ctx);
    if (!BN_set_word(zero, 0)) { ret = -1; goto err; }
    if (!BN_mod_sub(e, zero, e, order, ctx)) { ret = -1; goto err; }
    rr = BN_CTX_get(ctx);
    if (!BN_mod_inverse(rr, r, order, ctx)) { ret = -1; goto err; }
    sor = BN_CTX_get(ctx);
    if (!BN_mod_mul(sor, s, rr, order, ctx)) { ret = -1; goto err; }
    eor = BN_CTX_get(ctx);
    if (!BN_mod_mul(eor, e, rr, order, ctx)) { ret = -1; goto err; }
    if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) { ret = -2; goto err; }
    if (!EC_KEY_set_public_key(eckey, Q)) { ret = -2; goto err; }

    ret = 1;

err:
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (R != NULL) EC_POINT_free(R);
    if (O != NULL) EC_POINT_free(O);
    if (Q != NULL) EC_POINT_free(Q);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (group) EC_GROUP_free(group);
#endif
    return ret;
}

// Create a compact signature (65 bytes)
bool CKey::SignCompact(uint256 hash, std::vector<unsigned char>& vchSig)
{
    bool fOk = false;
    ECDSA_SIG *sig = ECDSA_do_sign((unsigned char*)&hash, sizeof(hash), pkey);
    if (sig == NULL)
        return false;
    vchSig.clear();
    vchSig.resize(65, 0);
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    r = ECDSA_SIG_get0_r(sig);
    s = ECDSA_SIG_get0_s(sig);
#else
    ECDSA_SIG_get0(sig, &r, &s);
#endif
    int nBitsR = BN_num_bits(r);
    int nBitsS = BN_num_bits(s);
    if (nBitsR <= 256 && nBitsS <= 256)
    {
        int nRecId = -1;
        for (int i = 0; i < 4; i++)
        {
            CKey keyRec;
            keyRec.fSet = true;
            if (fCompressedPubKey)
                keyRec.SetCompressedPubKey();
            if (ECDSA_SIG_recover_key_GFp(keyRec.pkey, sig, (unsigned char*)&hash, sizeof(hash), i, 1) == 1)
                if (keyRec.GetPubKey() == this->GetPubKey())
                {
                    nRecId = i;
                    break;
                }
        }

        if (nRecId == -1)
            throw key_error("CKey::SignCompact() : unable to construct recoverable key");

        vchSig[0] = nRecId + 27 + (fCompressedPubKey ? 4 : 0);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        BN_bn2lebinpad(r, &vchSig[33 - (nBitsR + 7) / 8], 32);
        BN_bn2lebinpad(s, &vchSig[65 - (nBitsS + 7) / 8], 32);
#else
        BN_bn2bin(r, &vchSig[33 - (nBitsR + 7) / 8]);
        BN_bn2bin(s, &vchSig[65 - (nBitsS + 7) / 8]);
#endif
        fOk = true;
    }
    ECDSA_SIG_free(sig);
    return fOk;
}

// Reconstruct public key from a compact signature
bool CKey::SetCompactSignature(uint256 hash, const std::vector<unsigned char>& vchSig)
{
    if (vchSig.size() != 65)
        return false;
    int nV = vchSig[0];
    if (nV < 27 || nV >= 35)
        return false;
    ECDSA_SIG *sig = ECDSA_SIG_new();
    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    if (!BN_lebin2bn(&vchSig[1], 32, r) || !BN_lebin2bn(&vchSig[33], 32, s))
#else
    if (!BN_bin2bn(&vchSig[1], 32, r) || !BN_bin2bn(&vchSig[33], 32, s))
#endif
    {
        ECDSA_SIG_free(sig);
        BN_free(r);
        BN_free(s);
        return false;
    }
    if (!ECDSA_SIG_set0(sig, r, s))
    {
        ECDSA_SIG_free(sig);
        BN_free(r);
        BN_free(s);
        return false;
    }

    EC_KEY_free(pkey);
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (nV >= 31)
    {
        SetCompressedPubKey();
        nV -= 4;
    }
    if (ECDSA_SIG_recover_key_GFp(pkey, sig, (unsigned char*)&hash, sizeof(hash), nV - 27, 0) == 1)
    {
        fSet = true;
        ECDSA_SIG_free(sig);
        return true;
    }
    ECDSA_SIG_free(sig);
    return false;
}

void CKey::SetCompressedPubKey()
{
    EC_KEY_set_conv_form(pkey, POINT_CONVERSION_COMPRESSED);
    fCompressedPubKey = true;
}

void CKey::Reset()
{
    fCompressedPubKey = false;
    if (pkey != NULL)
        EC_KEY_free(pkey);
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (pkey == NULL)
        throw key_error("CKey::CKey() : EC_KEY_new_by_curve_name failed");
    fSet = false;
}

CKey::CKey()
{
    pkey = NULL;
    Reset();
}

CKey::CKey(const CKey& b)
{
    pkey = EC_KEY_dup(b.pkey);
    if (pkey == NULL)
        throw key_error("CKey::CKey(const CKey&) : EC_KEY_dup failed");
    fSet = b.fSet;
}

CKey& CKey::operator=(const CKey& b)
{
    if (!EC_KEY_copy(pkey, b.pkey))
        throw key_error("CKey::operator=(const CKey&) : EC_KEY_copy failed");
    fSet = b.fSet;
    return (*this);
}

CKey::~CKey()
{
    EC_KEY_free(pkey);
}

bool CKey::IsNull() const
{
    return !fSet;
}

bool CKey::IsCompressed() const
{
    return fCompressedPubKey;
}

void CKey::MakeNewKey(bool fCompressed)
{
    if (!EC_KEY_generate_key(pkey))
        throw key_error("CKey::MakeNewKey() : EC_KEY_generate_key failed");
    if (fCompressed)
        SetCompressedPubKey();
    fSet = true;
}

bool CKey::SetPrivKey(const CPrivKey& vchPrivKey)
{
    const unsigned char* pbegin = &vchPrivKey[0];
    if (d2i_ECPrivateKey(&pkey, &pbegin, vchPrivKey.size()))
    {
        if (EC_KEY_check_key(pkey))
        {
            fSet = true;
            return true;
        }
    }
    pkey = NULL;
    Reset();
    return false;
}

bool CKey::SetSecret(const CSecret& vchSecret, bool fCompressed)
{
    EC_KEY_free(pkey);
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (pkey == NULL)
        throw key_error("CKey::SetSecret() : EC_KEY_new_by_curve_name failed");
    if (vchSecret.size() != 32)
        throw key_error("CKey::SetSecret() : secret must be 32 bytes");
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    BIGNUM *bn = BN_lebin2bn(&vchSecret[0], 32, BN_new());
#else
    BIGNUM *bn = BN_bin2bn(&vchSecret[0], 32, BN_new());
#endif
    if (bn == NULL)
        throw key_error("CKey::SetSecret() : BN_bin2bn failed");
    if (!EC_KEY_regenerate_key(pkey, bn))
    {
        BN_clear_free(bn);
        throw key_error("CKey::SetSecret() : EC_KEY_regenerate_key failed");
    }
    BN_clear_free(bn);
    fSet = true;
    if (fCompressed || fCompressedPubKey)
        SetCompressedPubKey();
    return true;
}

CSecret CKey::GetSecret(bool &fCompressed) const
{
    CSecret vchRet;
    vchRet.resize(32);
    const BIGNUM *bn = EC_KEY_get0_private_key(pkey);
    int nBytes = BN_num_bytes(bn);
    if (bn == NULL)
        throw key_error("CKey::GetSecret() : EC_KEY_get0_private_key failed");
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    int n = BN_bn2lebinpad(bn, &vchRet[0], 32);
#else
    int n = BN_bn2bin(bn, &vchRet[32 - nBytes]);
#endif
    if (n != 32)
        throw key_error("CKey::GetSecret(): BN_bn2bin failed");
    fCompressed = fCompressedPubKey;
    return vchRet;
}

CPrivKey CKey::GetPrivKey() const
{
    int nSize = i2d_ECPrivateKey(pkey, NULL);
    if (!nSize)
        throw key_error("CKey::GetPrivKey() : i2d_ECPrivateKey failed");
    CPrivKey vchPrivKey(nSize, 0);
    unsigned char* pbegin = &vchPrivKey[0];
    if (i2d_ECPrivateKey(pkey, &pbegin) != nSize)
        throw key_error("CKey::GetPrivKey() : i2d_ECPrivateKey returned unexpected size");
    return vchPrivKey;
}

bool CKey::SetPubKey(const CPubKey& vchPubKey)
{
    const unsigned char* pbegin = &vchPubKey.vchPubKey[0];
    if (o2i_ECPublicKey(&pkey, &pbegin, vchPubKey.vchPubKey.size()))
    {
        fSet = true;
        if (vchPubKey.vchPubKey.size() == 33)
            SetCompressedPubKey();
        return true;
    }
    pkey = NULL;
    Reset();
    return false;
}

CPubKey CKey::GetPubKey() const
{
    int nSize = i2o_ECPublicKey(pkey, NULL);
    if (!nSize)
        throw key_error("CKey::GetPubKey() : i2o_ECPublicKey failed");
    std::vector<unsigned char> vchPubKey(nSize, 0);
    unsigned char* pbegin = &vchPubKey[0];
    if (i2o_ECPublicKey(pkey, &pbegin) != nSize)
        throw key_error("CKey::GetPubKey() : i2o_ECPublicKey returned unexpected size");
    return CPubKey(vchPubKey);
}

bool CKey::Sign(uint256 hash, std::vector<unsigned char>& vchSig)
{
    unsigned int nSize = ECDSA_size(pkey);
    vchSig.resize(nSize);
    if (!ECDSA_sign(0, (unsigned char*)&hash, sizeof(hash), &vchSig[0], &nSize, pkey))
    {
        vchSig.clear();
        return false;
    }
    vchSig.resize(nSize);
    return true;
}

bool CKey::Verify(uint256 hash, const std::vector<unsigned char>& vchSig)
{
    if (ECDSA_verify(0, (unsigned char*)&hash, sizeof(hash), &vchSig[0], vchSig.size(), pkey) != 1)
        return false;
    return true;
}

bool CKey::VerifyCompact(uint256 hash, const std::vector<unsigned char>& vchSig)
{
    CKey key;
    if (!key.SetCompactSignature(hash, vchSig))
        return false;
    if (GetPubKey() != key.GetPubKey())
        return false;
    return true;
}

bool CKey::IsValid()
{
    if (!fSet)
        return false;
    if (!EC_KEY_check_key(pkey))
        return false;
    bool fCompr;
    CSecret secret = GetSecret(fCompr);
    CKey key2;
    key2.SetSecret(secret, fCompr);
    return GetPubKey() == key2.GetPubKey();
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
    if (pr != NULL)
        *pr = sig->r;
    if (ps != NULL)
        *ps = sig->s;
}
#endif
