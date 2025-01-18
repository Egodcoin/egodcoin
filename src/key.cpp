// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key.h"

#include "arith_uint256.h"
#include "crypto/common.h"
#include "crypto/hmac_sha512.h"
#include "pubkey.h"
#include "random.h"

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include <util.h>
#include <crypto/dilithium/api.h>

static secp256k1_context* secp256k1_context_sign = nullptr;

/** These functions are taken from the libsecp256k1 distribution and are very ugly. */
static int ec_privkey_import_der(const secp256k1_context* ctx, unsigned char *out32, const unsigned char *privkey, size_t privkeylen) {
    const unsigned char *end = privkey + privkeylen;
    int lenb = 0;
    int len = 0;
    memset(out32, 0, 32);
    /* sequence header */
    if (end < privkey+1 || *privkey != 0x30) {
        return 0;
    }
    privkey++;
    /* sequence length constructor */
    if (end < privkey+1 || !(*privkey & 0x80)) {
        return 0;
    }
    lenb = *privkey & ~0x80; privkey++;
    if (lenb < 1 || lenb > 2) {
        return 0;
    }
    if (end < privkey+lenb) {
        return 0;
    }
    /* sequence length */
    len = privkey[lenb-1] | (lenb > 1 ? privkey[lenb-2] << 8 : 0);
    privkey += lenb;
    if (end < privkey+len) {
        return 0;
    }
    /* sequence element 0: version number (=1) */
    if (end < privkey+3 || privkey[0] != 0x02 || privkey[1] != 0x01 || privkey[2] != 0x01) {
        return 0;
    }
    privkey += 3;
    /* sequence element 1: octet string, up to 32 bytes */
    if (end < privkey+2 || privkey[0] != 0x04 || privkey[1] > 0x20 || end < privkey+2+privkey[1]) {
        return 0;
    }
    memcpy(out32 + 32 - privkey[1], privkey + 2, privkey[1]);
    if (!secp256k1_ec_seckey_verify(ctx, out32)) {
        memset(out32, 0, 32);
        return 0;
    }
    return 1;
}

static int ec_privkey_export_der(const secp256k1_context *ctx, unsigned char *privkey, size_t *privkeylen, const unsigned char *key32, int compressed) {
    secp256k1_pubkey pubkey;
    size_t pubkeylen = 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key32)) {
        *privkeylen = 0;
        return 0;
    }
    if (compressed) {
        static const unsigned char begin[] = {
            0x30,0x81,0xD3,0x02,0x01,0x01,0x04,0x20
        };
        static const unsigned char middle[] = {
            0xA0,0x81,0x85,0x30,0x81,0x82,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x21,0x02,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x24,0x03,0x22,0x00
        };
        unsigned char *ptr = privkey;
        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        memcpy(ptr, key32, 32); ptr += 32;
        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
        pubkeylen = 33;
        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED);
        ptr += pubkeylen;
        *privkeylen = ptr - privkey;
    } else {
        static const unsigned char begin[] = {
            0x30,0x82,0x01,0x13,0x02,0x01,0x01,0x04,0x20
        };
        static const unsigned char middle[] = {
            0xA0,0x81,0xA5,0x30,0x81,0xA2,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x41,0x04,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,
            0x08,0xA8,0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,
            0xD4,0xB8,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x44,0x03,0x42,0x00
        };
        unsigned char *ptr = privkey;
        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        memcpy(ptr, key32, 32); ptr += 32;
        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
        pubkeylen = 65;
        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
        ptr += pubkeylen;
        *privkeylen = ptr - privkey;
    }
    return 1;
}

// Make new key generic.

bool CKey::Check(const unsigned char *vch) {
    return secp256k1_ec_seckey_verify(secp256k1_context_sign, vch);
}

void CKey::MakeNewKey(bool fCompressedIn) {
    switch(GetKeyType()) {
        case(KEY_TYPE_SECP_256_K1): {
            MakeNewKeySecp256k1(fCompressedIn);    
            break;
        }
        case(KEY_TYPE_DILITHIUM_3): {
            MakeNewKeyDilithium3(fCompressedIn);    
            break;
        }
        default: {
            throw std::runtime_error(std::string(__func__) + ": unknown key type " + std::to_string(GetKeyType()));
        }
    }
}

void CKey::MakeNewKeySecp256k1(bool fCompressedIn) {
    if (fLogKeysAndSign)
        LogPrintf("Key: Generate secp256k1 key.\n");

    assert(nKeyType == KEY_TYPE_SECP_256_K1);
    do {
        GetStrongRandBytes(keydata.data(), keydata.size());
    } while (!Check(keydata.data()));
    fValid = true;
    fCompressed = fCompressedIn;
}

// For Dilithium 3 keys.
// Unless MakeNewKey is called, GetPubKey().GetID().GetHex() is cb9f3b7c6fb1cf2c13a40637c189bdd066a272b4.
// This 'default' key must not be used for signing! 
void CKey::MakeNewKeyDilithium3(bool fCompressedIn) {
    if (fLogKeysAndSign)
        LogPrintf("Key: Generate Dilithium 3 key.\n");

    assert(nKeyType == KEY_TYPE_DILITHIUM_3);
    unsigned char sk[DILITHIUM_3_PRIVATE_KEY_SIZE];
    unsigned char pk[CPubKey::DILITHIUM_3_PUBLIC_KEY_SIZE];
    int r = PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_keypair(pk,sk);
    if (r != 0) {
        LogPrintf("Dilithium 3 key pair generation failed: (r != 0): r=%n.\n", r);
    }

    keydata.resize(DILITHIUM_3_PRIVATE_KEY_SIZE);
    memcpy(keydata.data(),sk, DILITHIUM_3_PRIVATE_KEY_SIZE);

    pubkeydata.resize(CPubKey::DILITHIUM_3_PUBLIC_KEY_SIZE);
    memcpy(pubkeydata.data(),pk, CPubKey::DILITHIUM_3_PUBLIC_KEY_SIZE);

    fValid = true;
    // TODO EGOD PQC Fix compressed or uncompressed. Is this the issue?
    fCompressed = true; // fCompressedIn;

    if (fLogKeysAndSign) {
        CPubKey pubkey1 = GetPubKeyDilithium3();
        LogPrintf("Key: Generated Dilithium 3 key (type=%i, key-id-hex=%s).\n", pubkey1.GetKeyType(), pubkey1.GetID().GetHex());
    }
}

// Get private key generic.

CPrivKey CKey::GetPrivKey() const {
    switch(GetKeyType()) {
        case(KEY_TYPE_SECP_256_K1): {
            return GetPrivKeySecp256k1();
        }
        case(KEY_TYPE_DILITHIUM_3): {
            return GetPrivKeyDilithium3();
        }
        default: {
            throw std::runtime_error(std::string(__func__) + ": unknown key type " + std::to_string(GetKeyType()));
        }
    }
}

CPrivKey CKey::GetPrivKeySecp256k1() const {
    if (fLogKeysAndSign)
        LogPrintf("Key: Get secp256k1 private key.\n");

    assert(nKeyType == KEY_TYPE_SECP_256_K1);
    assert(fValid);
    CPrivKey privkey;
    int ret;
    size_t privkeylen;
    privkey.resize(279);
    privkeylen = 279;
    ret = ec_privkey_export_der(secp256k1_context_sign, (unsigned char*) privkey.data(), &privkeylen, begin(), fCompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    assert(ret);
    privkey.resize(privkeylen);
    return privkey;
}

CPrivKey CKey::GetPrivKeyDilithium3() const {
    if (fLogKeysAndSign)
        LogPrintf("Key: Get Dilithium 3 private key.\n");

    assert(nKeyType == KEY_TYPE_DILITHIUM_3);
    assert(fValid);
    CPrivKey privkey;
    privkey.resize(DILITHIUM_3_PRIVATE_KEY_SIZE);
    memcpy(privkey.data(),keydata.data(), keydata.size());
    return privkey;
}

// Get public key generic.

CPubKey CKey::GetPubKey() const {
    switch(GetKeyType()) {
        case(KEY_TYPE_SECP_256_K1): {
            return GetPubKeySecp256k1();
        }
        case(KEY_TYPE_DILITHIUM_3): {
            return GetPubKeyDilithium3();
        }
        default: {
            throw std::runtime_error(std::string(__func__) + ": unknown key type " + std::to_string(GetKeyType()));
        }
    }
}

CPubKey CKey::GetPubKeySecp256k1() const {
    if (fLogKeysAndSign)
        LogPrintf("Key: Get secp256k1 public key.\n");

    assert(nKeyType == KEY_TYPE_SECP_256_K1);
    assert(fValid);
    secp256k1_pubkey pubkey;
    size_t clen = 65;
    CPubKey result = CPubKey(KEY_TYPE_SECP_256_K1);
    int ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pubkey, begin());
    assert(ret);
    secp256k1_ec_pubkey_serialize(secp256k1_context_sign, (unsigned char*)result.begin(), &clen, &pubkey, fCompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    assert(result.size() == clen);
    assert(result.IsValid());
    return result;
}

CPubKey CKey::GetPubKeyDilithium3() const {
    if (fLogKeysAndSign)
        LogPrintf("Key: Get Dilithium 3 public key.\n");

    assert(nKeyType == KEY_TYPE_DILITHIUM_3);
    assert(fValid);
    CPubKey pubkey = CPubKey(nKeyType);
    unsigned char* pch = (unsigned char *) pubkey.begin();

    SecureVector& ref = const_cast <SecureVector&>(pubkeydata);   
    ref.resize(CPubKey::DILITHIUM_3_PUBLIC_KEY_SIZE);
    memcpy(pch + 1, pubkeydata.data(), pubkeydata.size());

    pch[0] = 7;
    return pubkey;
}

// Sign generic.

bool CKey::Sign(const uint256 &hash, std::vector<unsigned char>& vchSig, uint32_t test_case) const {
    switch(GetKeyType()) {
        case(KEY_TYPE_SECP_256_K1): {
            return SignSecp256k1(hash, vchSig, test_case);
        }
        case(KEY_TYPE_DILITHIUM_3): {
            return SignDilithium3(hash, vchSig, false, test_case);
        }
        default: {
            throw std::runtime_error(std::string(__func__) + ": unknown key type " + std::to_string(GetKeyType()));
        }
    }
}

bool CKey::SignSecp256k1(const uint256 &hash, std::vector<unsigned char>& vchSig, uint32_t test_case) const {
    if (fLogKeysAndSign)
        LogPrintf("Key: Sign secp256k1.\n");

    assert(nKeyType == KEY_TYPE_SECP_256_K1);
    if (!fValid)
        return false;
    vchSig.resize(72);
    size_t nSigLen = 72;
    unsigned char extra_entropy[32] = {0};
    WriteLE32(extra_entropy, test_case);
    secp256k1_ecdsa_signature sig;
    int ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.begin(), begin(), secp256k1_nonce_function_rfc6979, test_case ? extra_entropy : nullptr);
    assert(ret);
    secp256k1_ecdsa_signature_serialize_der(secp256k1_context_sign, (unsigned char*)vchSig.data(), &nSigLen, &sig);
    vchSig.resize(nSigLen);
    return true;
}

bool CKey::SignDilithium3(const uint256 &hash, std::vector<unsigned char>& vchSig, bool grind, uint32_t test_case) const {
    if (fLogKeysAndSign)
        LogPrintf("Key: Sign Dilithium 3.\n");

    assert(nKeyType == KEY_TYPE_DILITHIUM_3);
    if (!fValid)
        return false;
    size_t sig_len;
    vchSig.resize(PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES_);
    int r = PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_signature(vchSig.data(),&sig_len,hash.begin() ,32,keydata.data());
    vchSig.resize(sig_len);

    if (r != 0) {
        LogPrintf("Dilithium 3 signature failed: (r != 0): r=%n.\n", r);
    }

    return true;
}

// Verify public key.

bool CKey::VerifyPubKey(const CPubKey& pubkey) const {
    switch(GetKeyType()) {
        case(KEY_TYPE_SECP_256_K1): {
            return VerifyPubKeySecp256k1(pubkey);
        }
        case(KEY_TYPE_DILITHIUM_3): {
            return VerifyPubKeyDilithium3(pubkey);
        }
        default: {
            throw std::runtime_error(std::string(__func__) + ": unknown key type " + std::to_string(GetKeyType()));
        }
    }
}

bool CKey::VerifyPubKeySecp256k1(const CPubKey& pubkey) const {
    if (fLogKeysAndSign)
        LogPrintf("Key: Verify secp256k1 public key (type=%i, key-id-hex=%s, pub-key-hash-hex=%s).\n", pubkey.GetKeyType(), pubkey.GetID().GetHex(), pubkey.GetHash().GetHex());

    assert(nKeyType == KEY_TYPE_SECP_256_K1);
    if (pubkey.IsCompressed() != fCompressed) {
        return false;
    }
    unsigned char rnd[8];
    std::string str = "Bitcoin key verification\n";
    GetRandBytes(rnd, sizeof(rnd));
    uint256 hash;
    CHash256().Write((unsigned char*)str.data(), str.size()).Write(rnd, sizeof(rnd)).Finalize(hash.begin());
    std::vector<unsigned char> vchSig;
    SignSecp256k1(hash, vchSig);
    return pubkey.VerifySecp256k1(hash, vchSig);
}

bool CKey::VerifyPubKeyDilithium3(const CPubKey& pubkey) const {
    if (fLogKeysAndSign)
        LogPrintf("Key: Verify Dilithium 3 public key (type=%i, key-id-hex=%s, pub-key-hash-hex=%s).\n", pubkey.GetKeyType(), pubkey.GetID().GetHex(), pubkey.GetHash().GetHex());

    assert(nKeyType == KEY_TYPE_DILITHIUM_3);
    unsigned char rnd[8];
    std::string str = "Bitcoin key verification\n";
    GetRandBytes(rnd, sizeof(rnd));
    uint256 hash;
    CHash256().Write((unsigned char*)str.data(), str.size()).Write(rnd, sizeof(rnd)).Finalize(hash.begin());
    std::vector<unsigned char> vchSig;
    SignDilithium3(hash, vchSig);
    return pubkey.VerifyDilithium3(hash, vchSig);
}

// Sign compact generic.

bool CKey::SignCompact(const uint256 &hash, std::vector<unsigned char>& vchSig) const {
    switch(GetKeyType()) {
        case(KEY_TYPE_SECP_256_K1): {
            return SignCompactSecp256k1(hash, vchSig);
        }
        case(KEY_TYPE_DILITHIUM_3): {
            return SignCompactDilithium3(hash, vchSig);
        }
        default: {
            throw std::runtime_error(std::string(__func__) + ": unknown key type " + std::to_string(GetKeyType()));
        }
    }
}

bool CKey::SignCompactSecp256k1(const uint256 &hash, std::vector<unsigned char>& vchSig) const {
    assert(nKeyType == KEY_TYPE_SECP_256_K1);
    if (!fValid)
        return false;
    vchSig.resize(65);
    int rec = -1;
    secp256k1_ecdsa_recoverable_signature sig;
    int ret = secp256k1_ecdsa_sign_recoverable(secp256k1_context_sign, &sig, hash.begin(), begin(), secp256k1_nonce_function_rfc6979, nullptr);
    assert(ret);
    secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_context_sign, (unsigned char*)&vchSig[1], &rec, &sig);
    assert(ret);
    assert(rec != -1);
    vchSig[0] = 27 + rec + (fCompressed ? 4 : 0);
    return true;
}

bool CKey::SignCompactDilithium3(const uint256 &hash, std::vector<unsigned char>& vchSig) const {
    assert(nKeyType == KEY_TYPE_DILITHIUM_3);
    if (!fValid)
        return false;
    size_t sig_len;
    vchSig.resize(PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES_+pksize());
    int r = PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_signature(vchSig.data(),&sig_len,hash.begin(),32,keydata.data());
    vchSig.resize(sig_len+pksize());
    memcpy(vchSig.data()+sig_len,pubkeydata.data(),pksize());
    if(r!=0){
        printf("\n--- sig is failed.%d\n",sig_len);
    }

    return true;
}

// Load generic.

bool CKey::Load(CPrivKey &privkey, CPubKey &vchPubKey, bool fSkipCheck=false) 
{
    switch(vchPubKey.GetKeyType()) {
        case(KEY_TYPE_SECP_256_K1): {
            nKeyType = KEY_TYPE_SECP_256_K1;
            return LoadSecp256k1(privkey, vchPubKey, fSkipCheck);
        }
        case(KEY_TYPE_DILITHIUM_3): {
            nKeyType = KEY_TYPE_DILITHIUM_3;
            return LoadDilithium3(privkey, vchPubKey, fSkipCheck);
        }
        default: {
            throw std::runtime_error(std::string(__func__) + ": unknown key type " + std::to_string(GetKeyType()));
        }
    }
}

bool CKey::LoadSecp256k1(CPrivKey &privkey, CPubKey &vchPubKey, bool fSkipCheck=false) {
    if (fLogKeysAndSign)
        LogPrintf("Key: Load secp256k1 key.\n");

    assert(nKeyType == KEY_TYPE_SECP_256_K1);
    if (!ec_privkey_import_der(secp256k1_context_sign, (unsigned char*)begin(), privkey.data(), privkey.size()))
        return false;
    fCompressed = vchPubKey.IsCompressed();
    fValid = true;

    if (fSkipCheck)
        return true;

    return VerifyPubKeySecp256k1(vchPubKey);
}

bool CKey::LoadDilithium3(const CPrivKey &seckey, const CPubKey &vchPubKey, bool fSkipCheck=false) {
    if (fLogKeysAndSign)
        LogPrintf("Key: Load Dilithium 3 key.\n");

    assert(nKeyType == KEY_TYPE_DILITHIUM_3);
    
    keydata.resize(DILITHIUM_3_PRIVATE_KEY_SIZE);
    memcpy((unsigned char*)begin(), seckey.data(), seckey.size());
    fCompressed = true; //vchPubKey.IsCompressed();
    fValid = true;

    pubkeydata.resize(CPubKey::DILITHIUM_3_PUBLIC_KEY_SIZE);
    memcpy((unsigned char*)pkbegin(), vchPubKey.data()+1, pksize());

    if (fSkipCheck)
        return true;

    return VerifyPubKeyDilithium3(vchPubKey);
}

// Only ECC.

bool CKey::Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const {
    assert(IsValid());
    assert(IsCompressed());
    std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
    if ((nChild >> 31) == 0) {
        CPubKey pubkey = GetPubKeySecp256k1();
        assert(pubkey.begin() + 33 == pubkey.end());
        BIP32Hash(cc, nChild, *pubkey.begin(), pubkey.begin()+1, vout.data());
    } else {
        assert(begin() + 32 == end());
        BIP32Hash(cc, nChild, 0, begin(), vout.data());
    }
    memcpy(ccChild.begin(), vout.data()+32, 32);
    memcpy((unsigned char*)keyChild.begin(), begin(), 32);
    bool ret = secp256k1_ec_privkey_tweak_add(secp256k1_context_sign, (unsigned char*)keyChild.begin(), vout.data());
    keyChild.fCompressed = true;
    keyChild.fValid = ret;
    return ret;
}

bool CExtKey::Derive(CExtKey &out, unsigned int _nChild) const {
    out.nDepth = nDepth + 1;
    CKeyID id = key.GetPubKeySecp256k1().GetID();
    memcpy(&out.vchFingerprint[0], &id, 4);
    out.nChild = _nChild;
    return key.Derive(out.key, out.chaincode, _nChild, chaincode);
}

void CExtKey::SetMaster(const unsigned char *seed, unsigned int nSeedLen) {
    static const unsigned char hashkey[] = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
    std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
    CHMAC_SHA512(hashkey, sizeof(hashkey)).Write(seed, nSeedLen).Finalize(vout.data());
    key.Set(vout.data(), vout.data() + 32, true);
    memcpy(chaincode.begin(), vout.data() + 32, 32);
    nDepth = 0;
    nChild = 0;
    memset(vchFingerprint, 0, sizeof(vchFingerprint));
}

CExtPubKey CExtKey::Neuter() const {
    CExtPubKey ret;
    ret.nDepth = nDepth;
    memcpy(&ret.vchFingerprint[0], &vchFingerprint[0], 4);
    ret.nChild = nChild;
    ret.pubkey = key.GetPubKeySecp256k1();
    ret.chaincode = chaincode;
    return ret;
}

void CExtKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const {
    if (fLogKeysAndSign)
        LogPrintf("Key: Encode.\n");

    code[0] = nDepth;
    memcpy(code+1, vchFingerprint, 4);
    code[5] = (nChild >> 24) & 0xFF; code[6] = (nChild >> 16) & 0xFF;
    code[7] = (nChild >>  8) & 0xFF; code[8] = (nChild >>  0) & 0xFF;
    memcpy(code + 9, chaincode.begin(), 32);
    code[41] = 0;
    assert(key.size() == 32);
    memcpy(code + 42, key.begin(), 32);
}

void CExtKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE]) {
    if (fLogKeysAndSign)
        LogPrintf("Key: Decode.\n");

    nDepth = code[0];
    memcpy(vchFingerprint, code + 1, 4);
    nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
    memcpy(chaincode.begin(), code + 9, 32);
    key.Set(code + 42, code+BIP32_EXTKEY_SIZE, true);
}

bool ECC_InitSanityCheck() {
    return InitSanityCheck(CKey(CKey::KEY_TYPE_SECP_256_K1));
}

bool PQC_InitSanityCheck() {
    return InitSanityCheck(CKey(CKey::KEY_TYPE_DILITHIUM_3));
}

bool InitSanityCheck(CKey key) {
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    return key.VerifyPubKey(pubkey);
}

void ECC_Start() {
    assert(secp256k1_context_sign == nullptr);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    assert(ctx != nullptr);

    {
        // Pass in a random blinding seed to the secp256k1 context.
        std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
        GetRandBytes(vseed.data(), 32);
        bool ret = secp256k1_context_randomize(ctx, vseed.data());
        assert(ret);
    }

    secp256k1_context_sign = ctx;
}

void ECC_Stop() {
    secp256k1_context *ctx = secp256k1_context_sign;
    secp256k1_context_sign = nullptr;

    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
}
