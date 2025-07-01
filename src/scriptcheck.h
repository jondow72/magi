#ifndef BITCOIN_SCRIPTCHECK_H
#define BITCOIN_SCRIPTCHECK_H

#include "main.h"   // Must be included before using CTxOut, CTransaction

class CScriptCheck
{
private:
    CTxOut txOut;
    CTransaction txTo;
    unsigned int nIn;
    unsigned int nFlags;
    bool fCacheStore;
    int nError;

public:
    CScriptCheck() : nIn(0), nFlags(0), fCacheStore(false), nError(0) {}
    CScriptCheck(const CTxOut& txoutIn, const CTransaction& txToIn, unsigned int nInIn, unsigned int nFlagsIn, bool fCacheStoreIn)
        : txOut(txoutIn), txTo(txToIn), nIn(nInIn), nFlags(nFlagsIn), fCacheStore(fCacheStoreIn), nError(0) {}

    bool operator()();

    void swap(CScriptCheck& check)
    {
        std::swap(txOut, check.txOut);
        std::swap(txTo, check.txTo);
        std::swap(nIn, check.nIn);
        std::swap(nFlags, check.nFlags);
        std::swap(fCacheStore, check.fCacheStore);
        std::swap(nError, check.nError);
    }

    int GetScriptError() const { return nError; }
};

#endif // BITCOIN_SCRIPTCHECK_H