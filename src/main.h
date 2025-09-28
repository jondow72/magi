static const int MAX_MAGI_POW_HEIGHT = 25000000;
static const int PRM_MAGI_POW_HEIGHT = 80000;
static const int PRM_MAGI_POW_HEIGHT_V2 = 50000; // re-cal PoW-I end block
static const int END_MAGI_POW_HEIGHT = 500000;
static const int END_MAGI_POW_HEIGHT_V2 = 5000000; // PoW-II aims to issue 12 mil and more than 10 years
static const int BLOCK_REWARD_ADJT = 2700;
static const int BLOCK_REWARD_ADJT_M7M_V2 = 32750;
static const unsigned int MAX_BLOCK_SIZE = 1000000;
static const unsigned int MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE/2;
static const unsigned int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE/50;
static const unsigned int MAX_ORPHAN_TRANSACTIONS = MAX_BLOCK_SIZE/100;
static const unsigned int MAX_INV_SZ = 50000;
static const int64 COINS_BURNED = 720000 * COIN; // Notes: https://bitcointalk.org/index.php?topic=735170.msg9475622#msg9475622
static const int64 MIN_TX_FEE = .0001 * COIN;
static const int64 MIN_RELAY_TX_FEE = MIN_TX_FEE;
static const int64 MAX_MONEY = 25000000 * COIN + COINS_BURNED;  // NOte: the amount of COINS_BURNED is unspendable
static const double MAX_MAGI_PROOF_OF_STAKE = 0.05;		// dynamic annual interest, max 5%
static const double MAX_MAGI_BALANCE_in_STAKE = 0.15;		// balance/money supply, max 15%
static const int64 MAX_MONEY_STAKE_REF = 5000000 * COIN;	// 5 mil
static const int64 MAX_MONEY_STAKE_REF_V2 = 500000 * COIN;	// 0.5 mil
static const int64 MIN_TXOUT_AMOUNT = MIN_TX_FEE;
static const int nCoinbaseMaturity = 100;            // 100 blocks
static const int nCoinbaseMaturityADJ = 500;            // 500 blocks
inline bool MoneyRange(int64 nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }
static const unsigned int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC
inline bool IsMiningProofOfWork(int nHeight)
{
    return nHeight <= MAX_MAGI_POW_HEIGHT;
}
inline bool IsMiningProofOfStake(int nHeight ) 
{
    if (fTestNet) return nHeight > 10;
    if (nHeight <= BLOCK_REWARD_ADJT) return (nHeight > 6720); // two weeks
    else return (nHeight > 10080); // three weeks
}
#define FORK_BLOCK_REWARDS_V2_TESNT 0
#define FORK_BLOCK_REWARDS_V2 1420650000
#define HEIGHT_CHAIN_SWITCH 1606950
#define HEIGHT_PROTOCOL_V3 1825100
inline bool IsPoWIIRewardProtocolV2(unsigned int nTime0)
{
    if (fTestNet) {
	   return (nTime0 > FORK_BLOCK_REWARDS_V2_TESNT);
    } else {
	   return (nTime0 > FORK_BLOCK_REWARDS_V2);
    }
}
inline bool IsPoSIIProtocolV2(int nHeight)
{
    if (fTestNet) {
    	if (nHeight > 40860) fTestNetWeightV2 = true;
	   else fTestNetWeightV2 = false;
	   return nHeight > 40780;
    } else return (nHeight > 131300);
}
inline bool IsProtocolV3(int nHeight)
{
    if (fTestNet) return true;
    return (nHeight > HEIGHT_PROTOCOL_V3);
}
inline bool IsBlockVersion5(int nHeight) { return fTestNet || nHeight > 1446791; }
inline unsigned int GetStakeMinAge(unsigned int nTime0) { return ( (nTime0 > 1503248400) ? (60 * 60 * 8) : (60 * 60 * 2) ); }
inline int64 GetMaxPoWWaitingTime()
{
    return (10 * 60); // Maximum time for PoW on hold
}
inline int64 GetMaxPoSWaitingTime()
{
    return (3 * 60); // Maximum time for PoS on hold
}
static const int64 nMaxClockDriftV1 = 2 * 60 * 60;      // two hours
static const int64 nMaxClockDriftV2 = 5 * 60;           // 5 mins
static const int64 nMaxClockDriftV3 = 30;               // 30 secs
inline int64 GetMaxClockDrift(int nHeight) 
{
    if (fTestNet) return nMaxClockDriftV3;
    if (nHeight > HEIGHT_CHAIN_SWITCH && nHeight <= HEIGHT_PROTOCOL_V3)
        return nMaxClockDriftV2;
    else if (nHeight > HEIGHT_PROTOCOL_V3)
        return nMaxClockDriftV3;
    return nMaxClockDriftV1;
}
inline int64 PastDrift(int64 nTime, int nHeight) { return ( nTime - GetMaxClockDrift(nHeight) ); }
inline int64 FutureDrift(int64 nTime, int nHeight) { return ( nTime + GetMaxClockDrift(nHeight) ); }
inline int64 FutureDriftCoinbaseV1(int64 nTime, int nHeight) { return ( nTime + nMaxClockDriftV1 ); }
inline int64 FutureDriftCoinbaseV2(int64 nTime, int nHeight) { return ( nTime + 30 * 60 ); }
inline int64 FutureDriftCoinbase(int64 nTime, int nHeight) 
{
    if (fTestNet) return FutureDriftCoinbaseV2(nTime, nHeight);
    if (nHeight > HEIGHT_PROTOCOL_V3)
        return FutureDriftCoinbaseV2(nTime, nHeight);
    return FutureDriftCoinbaseV1(nTime, nHeight);
}
inline bool IsChainAtSwitchPoint(int nHeight) { return (nHeight == HEIGHT_CHAIN_SWITCH); }
inline bool IsChainRuleSwitchedOff(int nHeight) { return (nHeight > HEIGHT_CHAIN_SWITCH); }
inline unsigned int GetStakeTargetSpacing(int nHeight) { return IsProtocolV3(nHeight) ? 96 : 90; }
int64 GetTargetSpacingWork(int nHeight);
int64 GetTargetSpacing(bool fProofOfStake);
int64 GetTargetTimespan(bool fProofOfStake);
void GenerateMagi(bool fGenerate, CWallet* pwallet);
bool CheckProofOfWork(uint256 hash, unsigned int nBits);
int64 GetProofOfWorkReward(int nBits, int nHeight, int64 nFees);
int64 GetProofOfWorkRewardV2(const CBlockIndex* pindexPrev, int64 nFees, bool fLastBlock);
int64 GetProofOfStakeReward(int64 nCoinAge, int64 nFees, CBlockIndex* pindex);
unsigned int ComputeMinWork(unsigned int nBase, int64 nTime);
unsigned int ComputeMinStake(unsigned int nBase, int64 nTime, unsigned int nBlockTime);
double GetDifficultyFromBitsV2(const CBlockIndex* pindex0, bool fPrintInfo=false);
double GetDifficultyFromBits(unsigned int nBits);
double GetAnnualInterest_TestNet(int64 nNetWorkWeit, double rMaxAPR);
double GetAnnualInterest(int64 nNetWorkWeit, double rMaxAPR);
double GetAnnualInterestV2(int64 nNetWorkWeit, double rMaxAPR, CBlockIndex* pindex0 = NULL);
bool IsChainInSwitch(const CBlockIndex* pindex_);