#include "scriptcheck.h"
#include "script.h"
#include "main.h"

bool CScriptCheck::operator()()
{
    // Use 0 for nHashType, as you do not need to specify a signature hash type for general verification
    return VerifyScript(
        txTo.vin[nIn].scriptSig,
        txOut.scriptPubKey,
        txTo,
        nIn,
        nFlags,
        0 // nHashType: set to 0 if you don't use it, or make sure it's valid in your context
    );
}
