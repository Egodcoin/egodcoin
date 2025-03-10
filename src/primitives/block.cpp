// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <primitives/block.h>
#include <primitives/powcache.h>
#include <sync.h>
#include <uint256.h>
#include <util.h>
#include <utilstrencodings.h>

#include <crypto/common.h>
#include <crypto/scrypt.h>

int ALGO = ALGO_GHOSTRIDER;

uint256 CBlockHeader::GetHash() const
{
	return SerializeHash(*this);
}

uint256 CBlockHeader::ComputeHash(int algo) const
{
    switch (algo)
    {
        case ALGO_GHOSTRIDER:
        {
            return HashGR(BEGIN(nVersion), END(nNonce), hashPrevBlock);
        }
        case ALGO_SCRYPT:
        {
            uint256 thash;
            scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(thash));
            return thash;
        }
        case ALGO_SHA256D:
        {
            return GetHash();
        }
    }
    return HashGR(BEGIN(nVersion), END(nNonce), hashPrevBlock);
}

uint256 CBlockHeader::GetPOWHash(int algo, bool readCache) const
{
    LOCK(cs_pow);
    CPowCache& cache(CPowCache::Instance());

    uint256 headerHash = GetHash();
    uint256 powHash;
    bool found = false;

    if (readCache) {
        found = cache.get(headerHash, powHash);
    }

    if (!found || cache.IsValidate()) {
        uint256 powHash2 = ComputeHash(algo);
        if (found && powHash2 != powHash) {
           LogPrintf("PowCache failure: headerHash: %s, from cache: %s, computed: %s, correcting\n", headerHash.ToString(), powHash.ToString(), powHash2.ToString());
        }
        powHash = powHash2;
        cache.erase(headerHash); // If it exists, replace it
        cache.insert(headerHash, powHash2);
    }
    return powHash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
