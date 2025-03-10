// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pubkey.h"

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include <util.h>
#include <crypto/dilithium/api.h>

namespace
{
/* Global secp256k1_context object used for verification. */
secp256k1_context* secp256k1_context_verify = nullptr;
} // namespace

/** This function is taken from the libsecp256k1 distribution and implements
 *  DER parsing for ECDSA signatures, while supporting an arbitrary subset of
 *  format violations.
 *
 *  Supported violations include negative integers, excessive padding, garbage
 *  at the end, and overly long length descriptors. This is safe to use in
 *  Bitcoin because since the activation of BIP66, signatures are verified to be
 *  strict DER before being passed to this module, and we know it supports all
 *  violations present in the blockchain before that point.
 */
static int ecdsa_signature_parse_der_lax(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen) {
    size_t rpos, rlen, spos, slen;
    size_t pos = 0;
    size_t lenbyte;
    unsigned char tmpsig[64] = {0};
    int overflow = 0;

    /* Hack to initialize sig with a correctly-parsed but invalid signature. */
    secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);

    /* Sequence tag byte */
    if (pos == inputlen || input[pos] != 0x30) {
        return 0;
    }
    pos++;

    /* Sequence length bytes */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (pos + lenbyte > inputlen) {
            return 0;
        }
        pos += lenbyte;
    }

    /* Integer tag byte for R */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for R */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (pos + lenbyte > inputlen) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        if (lenbyte >= sizeof(size_t)) {
            return 0;
        }
        rlen = 0;
        while (lenbyte > 0) {
            rlen = (rlen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        rlen = lenbyte;
    }
    if (rlen > inputlen - pos) {
        return 0;
    }
    rpos = pos;
    pos += rlen;

    /* Integer tag byte for S */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for S */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (pos + lenbyte > inputlen) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        if (lenbyte >= sizeof(size_t)) {
            return 0;
        }
        slen = 0;
        while (lenbyte > 0) {
            slen = (slen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        slen = lenbyte;
    }
    if (slen > inputlen - pos) {
        return 0;
    }
    spos = pos;
    pos += slen;

    /* Ignore leading zeroes in R */
    while (rlen > 0 && input[rpos] == 0) {
        rlen--;
        rpos++;
    }
    /* Copy R value */
    if (rlen > 32) {
        overflow = 1;
    } else {
        memcpy(tmpsig + 32 - rlen, input + rpos, rlen);
    }

    /* Ignore leading zeroes in S */
    while (slen > 0 && input[spos] == 0) {
        slen--;
        spos++;
    }
    /* Copy S value */
    if (slen > 32) {
        overflow = 1;
    } else {
        memcpy(tmpsig + 64 - slen, input + spos, slen);
    }

    if (!overflow) {
        overflow = !secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    if (overflow) {
        /* Overwrite the result again with a correctly-parsed but invalid
           signature if parsing failed. */
        memset(tmpsig, 0, 64);
        secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    return 1;
}

// Verify public key generic.

bool CPubKey::Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig) const {
    switch(GetKeyType()) {
        case(KEY_TYPE_SECP_256_K1): {
            return VerifySecp256k1(hash, vchSig);
        }
        case(KEY_TYPE_DILITHIUM_3): {
            return VerifyDilithium3(hash, vchSig);
        }
        default: {
            throw std::runtime_error(std::string(__func__) + ": unknown key type " + std::to_string(GetKeyType()));
        }
    }
}

bool CPubKey::VerifySecp256k1(const uint256 &hash, const std::vector<unsigned char>& vchSig) const {
    if (fLogKeysAndSign)
        LogPrintf("PubKey: Verify secp256k1.\n");

    assert(nKeyType == KEY_TYPE_SECP_256_K1);
    if (!IsValid())
        return false;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, &(*this)[0], size())) {
        return false;
    }
    if (!ecdsa_signature_parse_der_lax(secp256k1_context_verify, &sig, vchSig.data(), vchSig.size())) {
        return false;
    }
    /* libsecp256k1's ECDSA verification requires lower-S signatures, which have
     * not historically been enforced in Bitcoin, so normalize them first. */
    secp256k1_ecdsa_signature_normalize(secp256k1_context_verify, &sig, &sig);
    return secp256k1_ecdsa_verify(secp256k1_context_verify, &sig, hash.begin(), &pubkey);
}

bool CPubKey::VerifyDilithium3(const uint256 &hash, const std::vector<unsigned char>& vchSig) const {
    if (fLogKeysAndSign)
        LogPrintf("PubKey: Verify Dilithium 3.\n");

    assert(nKeyType == KEY_TYPE_DILITHIUM_3);
    if (!IsValid()) {
        LogPrintf("DILITHIUM 3 key verification failed (invalid=true)\n.");
        return false;
    }
    if (vchSig.size() != DILITHIUM_3_COMPACT_SIGNATURE_SIZE) {
        LogPrintf("DILITHIUM 3 key verification failed (vch-sig-size=%i)\n.", vchSig.size());
        return false;
    }
    int r = PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_verify(vchSig.data(),vchSig.size(),hash.begin(),32,begin()+1);
    if (r == 0) {
        return true;
    } else {
        LogPrintf("DILITHIUM 3 key verification failed (r=%i)\n.", r);
        return false;
    }
}

// Recover compact generic.

bool CPubKey::RecoverCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig) {
    switch(GetKeyType()) {
        case(KEY_TYPE_SECP_256_K1): {
            return RecoverCompactSecp256k1(hash, vchSig);
        }
        case(KEY_TYPE_DILITHIUM_3): {
            return RecoverCompactDilithium3(hash, vchSig);
        }
        default: {
            throw std::runtime_error(std::string(__func__) + ": unknown key type " + std::to_string(GetKeyType()));
        }
    }
}

bool CPubKey::RecoverCompactSecp256k1(const uint256 &hash, const std::vector<unsigned char>& vchSig) {
    if (fLogKeysAndSign)
        LogPrintf("PubKey: Recover compact secp256k1.\n");

    assert(nKeyType == KEY_TYPE_SECP_256_K1);
    if (vchSig.size() != 65)
        return false;
    int recid = (vchSig[0] - 27) & 3;
    bool fComp = ((vchSig[0] - 27) & 4) != 0;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_context_verify, &sig, &vchSig[1], recid)) {
        return false;
    }
    if (!secp256k1_ecdsa_recover(secp256k1_context_verify, &pubkey, &sig, hash.begin())) {
        return false;
    }
    unsigned char pub[65];
    size_t publen = 65;
    secp256k1_ec_pubkey_serialize(secp256k1_context_verify, pub, &publen, &pubkey, fComp ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    Set(pub, pub + publen);
    return true;
}

bool CPubKey::RecoverCompactDilithium3(const uint256 &hash, const std::vector<unsigned char>& vchSig) {
    if (fLogKeysAndSign)
        LogPrintf("PubKey: Recover compact Dilithium 3.\n");

    assert(nKeyType == KEY_TYPE_DILITHIUM_3);
    unsigned int mlen = vchSig.size()-(DILITHIUM_3_PUBLIC_KEY_SIZE-1);
    if (mlen != DILITHIUM_3_COMPACT_SIGNATURE_SIZE)
        return false;
    unsigned char *pch=(unsigned char *)begin();
    memcpy(pch+1, vchSig.data()+mlen, DILITHIUM_3_PUBLIC_KEY_SIZE-1);
    pch[0]=7;
    
    int r = PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_verify(vchSig.data(), mlen, hash.begin(), 32, pch + 1);
    if (r == 0) {
        return true;
    } else {
        //LogPrintf("\n--- RecoverCompact verify is failed.\n");
        return false;
    }
}

bool CPubKey::IsFullyValid() const {
    if (!IsValid())
        return false;
    secp256k1_pubkey pubkey;
    return secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, &(*this)[0], size());
}

bool CPubKey::Decompress() {
    if (fLogKeysAndSign)
        LogPrintf("PubKey: Decompress.\n");

    if (!IsValid())
        return false;
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, &(*this)[0], size())) {
        return false;
    }
    unsigned char pub[65];
    size_t publen = 65;
    secp256k1_ec_pubkey_serialize(secp256k1_context_verify, pub, &publen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    Set(pub, pub + publen);
    return true;
}

bool CPubKey::Derive(CPubKey& pubkeyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const {
    assert(IsValid());
    assert((nChild >> 31) == 0);
    assert(begin() + 33 == end());
    unsigned char out[64];
    BIP32Hash(cc, nChild, *begin(), begin()+1, out);
    memcpy(ccChild.begin(), out+32, 32);
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, &(*this)[0], size())) {
        return false;
    }
    if (!secp256k1_ec_pubkey_tweak_add(secp256k1_context_verify, &pubkey, out)) {
        return false;
    }
    unsigned char pub[33];
    size_t publen = 33;
    secp256k1_ec_pubkey_serialize(secp256k1_context_verify, pub, &publen, &pubkey, SECP256K1_EC_COMPRESSED);
    pubkeyChild.Set(pub, pub + publen);
    return true;
}

// TODO EGOD PQC for secp256k1.
// void CExtPubKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const {
//     code[0] = nDepth;
//     memcpy(code+1, vchFingerprint, 4);
//     code[5] = (nChild >> 24) & 0xFF; code[6] = (nChild >> 16) & 0xFF;
//     code[7] = (nChild >>  8) & 0xFF; code[8] = (nChild >>  0) & 0xFF;
//     memcpy(code+9, chaincode.begin(), 32);
//     assert(pubkey.size() == 33);
//     memcpy(code+41, pubkey.begin(), 33);
// }

// void CExtPubKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE]) {
//     nDepth = code[0];
//     memcpy(vchFingerprint, code+1, 4);
//     nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
//     memcpy(chaincode.begin(), code+9, 32);
//     pubkey.Set(code+41, code+BIP32_EXTKEY_SIZE);
// }

void CExtPubKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const {
    if (fLogKeysAndSign)
        LogPrintf("PubKey: Encode.\n");

    code[0] = nDepth;
    memcpy(code+1, vchFingerprint, 4);
    code[5] = (nChild >> 24) & 0xFF; code[6] = (nChild >> 16) & 0xFF;
    code[7] = (nChild >>  8) & 0xFF; code[8] = (nChild >>  0) & 0xFF;
    memcpy(code+9, chaincode.begin(), 32);
    assert(pubkey.size() == CPubKey::DILITHIUM_3_PUBLIC_KEY_COMPRESSED_SIZE);
    memcpy(code+41, pubkey.begin(), CPubKey::DILITHIUM_3_PUBLIC_KEY_COMPRESSED_SIZE);
}

void CExtPubKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE]) {
    if (fLogKeysAndSign)
        LogPrintf("PubKey: Decode.\n");

    nDepth = code[0];
    memcpy(vchFingerprint, code+1, 4);
    nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
    memcpy(chaincode.begin(), code+9, 32);
    pubkey.Set(code+41, code+BIP32_EXTKEY_SIZE);
}


bool CExtPubKey::Derive(CExtPubKey &out, unsigned int _nChild) const {
    out.nDepth = nDepth + 1;
    CKeyID id = pubkey.GetID();
    memcpy(&out.vchFingerprint[0], &id, 4);
    out.nChild = _nChild;
    return pubkey.Derive(out.pubkey, out.chaincode, _nChild, chaincode);
}

bool CPubKey::CheckLowS(const std::vector<unsigned char>& vchSig) {
    secp256k1_ecdsa_signature sig;
    if (!ecdsa_signature_parse_der_lax(secp256k1_context_verify, &sig, vchSig.data(), vchSig.size())) {
        return false;
    }
    return (!secp256k1_ecdsa_signature_normalize(secp256k1_context_verify, nullptr, &sig));
}

/* static */ int ECCVerifyHandle::refcount = 0;

ECCVerifyHandle::ECCVerifyHandle()
{
    if (refcount == 0) {
        assert(secp256k1_context_verify == nullptr);
        secp256k1_context_verify = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        assert(secp256k1_context_verify != nullptr);
    }
    refcount++;
}

ECCVerifyHandle::~ECCVerifyHandle()
{
    refcount--;
    if (refcount == 0) {
        assert(secp256k1_context_verify != nullptr);
        secp256k1_context_destroy(secp256k1_context_verify);
        secp256k1_context_verify = nullptr;
    }
}
