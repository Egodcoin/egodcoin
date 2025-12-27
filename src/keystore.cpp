// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "keystore.h"
#include "base58.h"
#include "key.h"
#include "pubkey.h"
#include "util.h"

bool CKeyStore::AddKey(const CKey &key) {
    return AddKeyPubKey(key, key.GetPubKey());
}

bool CBasicKeyStore::GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
    CKey key;
    if (!GetKey(address, key)) {
        LogPrintf("CBasicKeyStore::GetPubKey: Failed to get key (btcAddress=%s, key-id-hex=%s).\n", CBitcoinAddress(address).ToString(), address.GetHex());
        LOCK(cs_KeyStore);
        WatchKeyMap::const_iterator it = mapWatchKeys.find(address);
        if (it != mapWatchKeys.end()) {
            vchPubKeyOut = it->second;
            LogPrintf("CBasicKeyStore::GetPubKey: Next key from watchlist (key-id-hex=%s, pub-key-hash-hex=%s).\n", vchPubKeyOut.GetID().GetHex(), vchPubKeyOut.GetHash().GetHex());
            return true;
        }
        return false;
    }

    vchPubKeyOut = key.GetPubKey();
    CScript test = CScript(vchPubKeyOut.begin(), vchPubKeyOut.end());
    std::string scriptString(test.begin(), test.end());

    if (fLogKeysAndSign)
        LogPrintf("Keystore: GetPubKey (type=%d, key-id-hex=%s, pub-key-hash-hex=%s, script=%s).\n", vchPubKeyOut.GetKeyType(), vchPubKeyOut.GetID().GetHex(), vchPubKeyOut.GetHash().GetHex(), scriptString);

    assert(address.GetHex() == vchPubKeyOut.GetID().GetHex());

    return true;
}

bool CBasicKeyStore::AddKeyPubKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore);

    assert(key.GetPubKey().GetID().GetHex() == pubkey.GetID().GetHex());
    mapKeys[pubkey.GetID()] = key;
    return true;
}

bool CBasicKeyStore::AddCScript(const CScript& redeemScript)
{
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
        return error("CBasicKeyStore::AddCScript(): redeemScripts > %i bytes are invalid", MAX_SCRIPT_ELEMENT_SIZE);

    LOCK(cs_KeyStore);
    mapScripts[CScriptID(redeemScript)] = redeemScript;
    return true;
}

bool CBasicKeyStore::HaveCScript(const CScriptID& hash) const
{
    LOCK(cs_KeyStore);
    return mapScripts.count(hash) > 0;
}

bool CBasicKeyStore::GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const
{
    LOCK(cs_KeyStore);
    ScriptMap::const_iterator mi = mapScripts.find(hash);
    if (mi != mapScripts.end())
    {
        redeemScriptOut = (*mi).second;
        return true;
    }
    return false;
}

static bool ExtractPubKey(const CScript &dest, CPubKey& pubKeyOut)
{
    if (fLogKeysAndSign)
        LogPrintf("Keystore: ExtractPubKey.\n");

    // TODO: Use Solver to extract this?
    CScript::const_iterator pc = dest.begin();
    opcodetype opcode;
    std::vector<unsigned char> vch;
    if (!dest.GetOp(pc, opcode, vch) || vch.size() < 33 || vch.size() > 65)
        return false;
    pubKeyOut = CPubKey(vch);
    if (!pubKeyOut.IsFullyValid())
        return false;
    if (!dest.GetOp(pc, opcode, vch) || opcode != OP_CHECKSIG || dest.GetOp(pc, opcode, vch))
        return false;
    return true;
}

// TODO EGOD PQC User Solver here.
// static bool ExtractPubKey(const CScript &dest, CPubKey& pubKeyOut)
// {
//     if (fLogKeysAndSign)
//         LogPrintf("Keystore: ExtractPubKey.\n");

//     std::vector<std::vector<unsigned char>> solutions;
//     return Solver(dest, solutions) == TxoutType::PUBKEY &&
//         (pubKeyOut = CPubKey(solutions[0])).IsFullyValid();
// }

bool CBasicKeyStore::AddWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.insert(dest);
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey))
        mapWatchKeys[pubKey.GetID()] = pubKey;
    return true;
}

bool CBasicKeyStore::RemoveWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.erase(dest);
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey))
        mapWatchKeys.erase(pubKey.GetID());
    return true;
}

bool CBasicKeyStore::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore);
    return setWatchOnly.count(dest) > 0;
}

bool CBasicKeyStore::HaveWatchOnly() const
{
    LOCK(cs_KeyStore);
    return (!setWatchOnly.empty());
}

bool CBasicKeyStore::GetHDChain(CHDChain& hdChainRet) const
{
    hdChainRet = hdChain;
    return !hdChain.IsNull();
}
