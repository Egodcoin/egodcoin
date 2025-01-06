// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PUBKEY_H
#define BITCOIN_PUBKEY_H

#include "hash.h"
#include "serialize.h"
#include "uint256.h"
#include "crypto/dilithium/span.h"

#include <stdexcept>
#include <vector>

#include <util.h>

/**
 * secp256k1:
 * const unsigned int PRIVATE_KEY_SIZE = 279;
 * const unsigned int PUBLIC_KEY_SIZE  = 65;
 * const unsigned int SIGNATURE_SIZE   = 72;
 *
 * see www.keylength.com
 * script supports up to 75 for single byte push
 */

const unsigned int BIP32_EXTKEY_SIZE = 74;

/** A reference to a CKey: the Hash160 of its serialized public key */
class CKeyID : public uint160
{
public:
    CKeyID() : uint160() {}
    CKeyID(const uint160& in) : uint160(in) {}
};

typedef uint256 ChainCode;

/** An encapsulated public key. */
class CPubKey
{
public:

    static const unsigned int KEY_TYPE_SECP_256_K1                          = 0;
    static const unsigned int KEY_TYPE_DILITHIUM_3                          = 1;

    static constexpr unsigned int SECP_256_K1_PUBLIC_KEY_SIZE               = 65;
    static constexpr unsigned int SECP_256_K1_PUBLIC_KEY_COMPRESSED_SIZE    = 33;

    static constexpr unsigned int DILITHIUM_3_PUBLIC_KEY_SIZE               = 1952 + 1;
    static constexpr unsigned int DILITHIUM_3_PUBLIC_KEY_COMPRESSED_SIZE    = 1952 + 1;
    static constexpr unsigned int DILITHIUM_3_SIGNATURE_SIZE                = 3293;
    static constexpr unsigned int DILITHIUM_3_COMPACT_SIGNATURE_SIZE        = 3293;

    unsigned int GetKeyType() const { return nKeyType; }
    void SetKeyType(unsigned int type) { nKeyType = type; }

private:

    unsigned int nKeyType = nDefaultKeyType;

    /**
     * Just store the serialized data.
     * Its length can very cheaply be computed from the first byte.
     */
    // TODO EGOD PQC For secp256k1. Is resized later.
    // unsigned char vch[65];
    unsigned char vch[DILITHIUM_3_PUBLIC_KEY_SIZE];

    unsigned int static GetLenDilithium3(unsigned char chHeader)
    {
        if (chHeader == 2 || chHeader == 3)
            return 1952 + 1;
        if (chHeader == 4 || chHeader == 6 || chHeader == 7)
            return 1952 + 1;
        return 0;
    }

    unsigned int static GetLenSecp256k1(unsigned char chHeader)
    {
        if (chHeader == 2 || chHeader == 3)
            return SECP_256_K1_PUBLIC_KEY_COMPRESSED_SIZE;
        if (chHeader == 4 || chHeader == 6 || chHeader == 7)
            return SECP_256_K1_PUBLIC_KEY_SIZE;
        return 0;
    }

    //! Set this key data to be invalid
    void Invalidate()
    {
        vch[0] = 0xFF;
    }

public:

    //! Construct an invalid public key.
    CPubKey()
    {
        Invalidate();
        nKeyType = nDefaultKeyType;
    }

    CPubKey(int nKeyTypeIn)
    {
        Invalidate();
        nKeyType = nKeyTypeIn;
    }

    //! Initialize a public key using begin/end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend)
    {
        int getLen = -1;
        if (nKeyType == KEY_TYPE_SECP_256_K1) {
            getLen = GetLenSecp256k1(pbegin[0]);
        } else if (nKeyType == KEY_TYPE_DILITHIUM_3) {
            getLen = GetLenDilithium3(pbegin[0]);  
        }
        
        int len = pend == pbegin ? 0 : getLen;

        if (fLogKeysAndSign)
            LogPrintf("PubKey: Set (get-key-type=%d, len=%i, getLen=%d).\n", GetKeyType(), len, getLen);

        if (len && len == (pend - pbegin))
            memcpy(vch, (unsigned char*) & pbegin[0], len);
        else {
            Invalidate();
        }
    }

    //! Construct a public key using begin/end iterators to byte data.
    template <typename T>
    CPubKey(const T pbegin, const T pend)
    {
        Set(pbegin, pend);
    }

    //! Construct a public key from a byte vector.
    CPubKey(const std::vector<unsigned char>& _vch)
    {
        nKeyType = nDefaultKeyType;
        Set(_vch.begin(), _vch.end());
    }

    //! Simple read-only vector-like interface to the pubkey data.
    unsigned int size() const {
        switch(GetKeyType()) {
            case(KEY_TYPE_SECP_256_K1): {
                return GetLenSecp256k1(vch[0]);
            }
            case(KEY_TYPE_DILITHIUM_3): {
                return GetLenDilithium3(vch[0]);
            }
            default: {
                throw std::runtime_error(std::string(__func__) + ": unknown key type " + std::to_string(GetKeyType()));
            }
        }
    }

    const unsigned char* data() const { return vch; }
    const unsigned char* begin() const { return vch; }
    const unsigned char* end() const { return vch + size(); }
    const unsigned char& operator[](unsigned int pos) const { return vch[pos]; }

    //! Comparator implementation.
    friend bool operator==(const CPubKey& a, const CPubKey& b)
    {
        return a.vch[0] == b.vch[0] &&
               memcmp(a.vch, b.vch, a.size()) == 0;
    }
    friend bool operator!=(const CPubKey& a, const CPubKey& b)
    {
        return !(a == b);
    }
    friend bool operator<(const CPubKey& a, const CPubKey& b)
    {
        return a.vch[0] < b.vch[0] ||
               (a.vch[0] == b.vch[0] && memcmp(a.vch, b.vch, a.size()) < 0);
    }

    //! Implement serialization, as if this was a byte vector.
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        unsigned int len = size();
        ::WriteCompactSize(s, len);
        s.write((char*)vch, len);
    }

    // TODO EGOD PQC For secp256k1.
    // template <typename Stream>
    // void Unserialize(Stream& s)
    // {
    //     unsigned int len = ::ReadCompactSize(s);
    //     if (len <= SECP_256_K1_PUBLIC_KEY_SIZE) {
    //         s.read((char*)vch, len);
    //     } else {
    //         // invalid pubkey, skip available data
    //         char dummy;
    //         while (len--)
    //             s.read(&dummy, 1);
    //         Invalidate();
    //     }
    // }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        unsigned int len = ::ReadCompactSize(s);
        // TODO: Quick-fix for option for secp256k1.
        if (len == SECP_256_K1_PUBLIC_KEY_COMPRESSED_SIZE) {
            nKeyType = KEY_TYPE_SECP_256_K1;
        }

        if (len <= DILITHIUM_3_PUBLIC_KEY_SIZE) {
            s.read((char*)vch, len);
            if (len != size()) {
                Invalidate();
            }
        } else {
            if (fLogKeysAndSign)
                LogPrintf("PubKey: Unserialize (invalid=true, get-key-type=%d, len=%i, size=%d).\n", GetKeyType(), len, size());
            // invalid pubkey, skip available data
            char dummy;
            while (len--)
                s.read(&dummy, 1);
            Invalidate();
        }
    }

    //! Get the KeyID of this public key (hash of its serialization)
    CKeyID GetID() const
    {
        return CKeyID(Hash160(vch, vch + size()));
    }

    //! Get the 256-bit hash of this public key.
    uint256 GetHash() const
    {
        return Hash(vch, vch + size());
    }

    /*
     * Check syntactic correctness.
     *
     * Note that this is consensus critical as CheckSig() calls it!
     */
    bool IsValid() const
    {
        return size() > 0;
    }

    //! fully validate whether this is a valid public key (more expensive than IsValid())
    bool IsFullyValid() const;

    //! Check whether this is a compressed public key.
    bool IsCompressed() const
    {
        switch(GetKeyType()) {
            case(KEY_TYPE_SECP_256_K1): {
                return size() == SECP_256_K1_PUBLIC_KEY_COMPRESSED_SIZE;
            }
            case(KEY_TYPE_DILITHIUM_3): {
                return size() == DILITHIUM_3_PUBLIC_KEY_COMPRESSED_SIZE;
            }
            default: {
                throw std::runtime_error(std::string(__func__) + ": unknown key type " + std::to_string(GetKeyType()));
            }
        }
    }

    /**
     * Verify a DER signature (~72 bytes).
     * If this public key is not fully valid, the return value will be false.
     */
    bool Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig) const;

    bool VerifySecp256k1(const uint256& hash, const std::vector<unsigned char>& vchSig) const;

    bool VerifyDilithium3(const uint256& hash, const std::vector<unsigned char>& vchSig) const;

    /**
     * Check whether a signature is normalized (lower-S).
     */
    static bool CheckLowS(const std::vector<unsigned char>& vchSig);

    //! Recover a public key from a compact signature.
    bool RecoverCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig);

    bool RecoverCompactSecp256k1(const uint256& hash, const std::vector<unsigned char>& vchSig);

    bool RecoverCompactDilithium3(const uint256& hash, const std::vector<unsigned char>& vchSig);

    //! Turn this public key into an uncompressed public key.
    bool Decompress();

    //! Derive BIP32 child pubkey.
    bool Derive(CPubKey& pubkeyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const;
};

struct CExtPubKey {
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    ChainCode chaincode;
    CPubKey pubkey;

    friend bool operator==(const CExtPubKey &a, const CExtPubKey &b)
    {
        return a.nDepth == b.nDepth &&
            memcmp(&a.vchFingerprint[0], &b.vchFingerprint[0], sizeof(vchFingerprint)) == 0 &&
            a.nChild == b.nChild &&
            a.chaincode == b.chaincode &&
            a.pubkey == b.pubkey;
    }

    void Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const;
    void Decode(const unsigned char code[BIP32_EXTKEY_SIZE]);
    bool Derive(CExtPubKey& out, unsigned int nChild) const;

    void Serialize(CSizeComputer& s) const
    {
        // Optimized implementation for ::GetSerializeSize that avoids copying.
        s.seek(BIP32_EXTKEY_SIZE + 1); // add one byte for the size (compact int)
    }
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        unsigned int len = BIP32_EXTKEY_SIZE;
        ::WriteCompactSize(s, len);
        unsigned char code[BIP32_EXTKEY_SIZE];
        Encode(code);
        s.write((const char *)&code[0], len);
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        unsigned int len = ::ReadCompactSize(s);
        unsigned char code[BIP32_EXTKEY_SIZE];
        if (len != BIP32_EXTKEY_SIZE)
            throw std::runtime_error("Invalid extended key size\n");
        s.read((char *)&code[0], len);
        Decode(code);
    }
};

/** Users of this module must hold an ECCVerifyHandle. The constructor and
 *  destructor of these are not allowed to run in parallel, though. */
class ECCVerifyHandle
{
    static int refcount;

public:
    ECCVerifyHandle();
    ~ECCVerifyHandle();
};

#endif // BITCOIN_PUBKEY_H
