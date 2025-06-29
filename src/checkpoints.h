// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHECKPOINTS_H
#define BITCOIN_CHECKPOINTS_H

#include <map>
#include "uint256.h"

class CBlockIndex;

namespace Checkpoints
{
    // Returns true if the block at nHeight has the expected hash (static checkpoints only)
    bool CheckHardened(int nHeight, const uint256& hash);

    // Returns the estimated total number of blocks based on static checkpoints
    int GetTotalBlocksEstimate();

    // Returns the last CBlockIndex* for which a static checkpoint is defined
    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex);
}

#endif // BITCOIN_CHECKPOINTS_H
