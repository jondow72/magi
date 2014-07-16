#ifndef MAGI_SCRIPT_CHECK_H
#define MAGI_SCRIPT_CHECK_H

#include "script.h"
#include "main.h"
#include <stdint.h> // for int64_t

class CScriptCheck {
    CScript scriptPubKey;
    const CTransaction* ptto;
    unsigned int nIn;
    unsigned int nFlags;
    int nHashType;
    int64_t nValue; // <-- changed from CAmount

public:
    CScriptCheck()
        : ptto(nullptr), nIn(0), nFlags(0), nHashType(0), nValue(0) {}

    CScriptCheck(const CScript& scriptPubKeyIn, const CTransaction& txToIn,
                 unsigned int nInIn, unsigned int nFlagsIn, int nHashTypeIn = 0, int64_t nValueIn = 0)
        : scriptPubKey(scriptPubKeyIn), ptto(&txToIn), nIn(nInIn),
          nFlags(nFlagsIn), nHashType(nHashTypeIn), nValue(nValueIn) {}

    bool operator()() {
        // Placeholder: always returns true
        return true;
    }
};

#endif // MAGI_SCRIPT_CHECK_H