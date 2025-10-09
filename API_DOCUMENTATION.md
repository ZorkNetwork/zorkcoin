# Zorkcoin API Documentation

This document provides comprehensive documentation for all public APIs, functions, and components in the Zorkcoin codebase. Zorkcoin is a Bitcoin Core fork that implements additional features including MWEB (Mimblewimble Extension Blocks) and uses the kHeavyHash algorithm.

## Table of Contents

1. [Core Consensus APIs](#core-consensus-apis)
2. [Validation APIs](#validation-apis)
3. [RPC APIs](#rpc-apis)
4. [Wallet APIs](#wallet-apis)
5. [Network APIs](#network-apis)
6. [Cryptographic APIs](#cryptographic-apis)
7. [Qt GUI APIs](#qt-gui-apis)
8. [Utility APIs](#utility-apis)
9. [Examples and Usage](#examples-and-usage)

---

## Core Consensus APIs

### Consensus Constants

The consensus module defines critical constants that govern the blockchain protocol:

```cpp
// Maximum block size limits
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 4000000;
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE_WITH_MWEB = MAX_BLOCK_SERIALIZED_SIZE + mw::MAX_BLOCK_BYTES;
static const unsigned int MAX_BLOCK_WEIGHT = 4000000;
static const int64_t MAX_BLOCK_SIGOPS_COST = 80000;

// Maturity requirements
static const int COINBASE_MATURITY = 100;
static const int PEGOUT_MATURITY = 6;  // MWEB specific

// Transaction weight limits
static const size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60;
static const size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10;
```

**Usage Example:**
```cpp
#include <consensus/consensus.h>

// Check if a block size is valid
if (block_size <= MAX_BLOCK_SERIALIZED_SIZE) {
    // Block size is within consensus limits
}

// Check coinbase maturity
if (block_height >= COINBASE_MATURITY) {
    // Coinbase outputs can be spent
}
```

### Lock Time Flags

```cpp
// Sequence number interpretation
static constexpr unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);
static constexpr unsigned int LOCKTIME_MEDIAN_TIME_PAST = (1 << 1);
```

---

## Validation APIs

### Block Validation

The validation module provides comprehensive block and transaction validation functionality.

#### Core Validation Functions

```cpp
// Check block validity
bool CheckBlock(const CBlock& block, BlockValidationState& state, 
                const Consensus::Params& consensusParams, 
                bool fCheckPOW = true, bool fCheckMerkleRoot = true);

// Test block validity on current chain
bool TestBlockValidity(BlockValidationState& state, const CChainParams& chainparams, 
                       const CBlock& block, CBlockIndex* pindexPrev, 
                       bool fCheckPOW = true, bool fCheckMerkleRoot = true);

// Check if witness is enabled
bool IsWitnessEnabled(const CBlockIndex* pindexPrev, const Consensus::Params& params);

// Check if MWEB is enabled
bool IsMWEBEnabled(const CBlockIndex* pindexPrev, const Consensus::Params& params);
```

**Usage Example:**
```cpp
#include <validation.h>

CBlock block;
BlockValidationState state;
const Consensus::Params& params = Params().GetConsensus();

// Validate a block
if (CheckBlock(block, state, params)) {
    // Block is valid according to consensus rules
    std::cout << "Block validation passed" << std::endl;
} else {
    std::cout << "Block validation failed: " << state.ToString() << std::endl;
}

// Check if MWEB is active
if (IsMWEBEnabled(pindexPrev, params)) {
    // MWEB features are available
}
```

#### Transaction Validation

```cpp
// Check if transaction is final
bool CheckFinalTx(const CTransaction &tx, int flags = -1);

// Check sequence locks
bool CheckSequenceLocks(const CTxMemPool& pool, const CTransaction& tx, 
                        int flags, LockPoints* lp = nullptr, 
                        bool useExistingLockPoints = false);

// Accept transaction to memory pool
bool AcceptToMemoryPool(CTxMemPool& pool, TxValidationState &state, 
                        const CTransactionRef &tx,
                        std::list<CTransactionRef>* plTxnReplaced,
                        bool bypass_limits, bool test_accept=false, 
                        CAmount* fee_out=nullptr);
```

**Usage Example:**
```cpp
// Check if transaction is final
if (CheckFinalTx(tx)) {
    // Transaction can be included in next block
}

// Add transaction to mempool
TxValidationState state;
if (AcceptToMemoryPool(mempool, state, txRef, nullptr, false)) {
    // Transaction accepted to mempool
} else {
    // Transaction rejected: state.ToString() contains reason
}
```

### Chain State Management

#### CChainState Class

The `CChainState` class manages the blockchain state and UTXO set:

```cpp
class CChainState {
public:
    // Initialize UTXO database
    void InitCoinsDB(size_t cache_size_bytes, bool in_memory, 
                     bool should_wipe, std::string leveldb_name = "chainstate");
    
    // Initialize in-memory cache
    void InitCoinsCache(size_t cache_size_bytes);
    
    // Get UTXO view
    CCoinsViewCache& CoinsTip();
    CCoinsViewDB& CoinsDB();
    
    // Activate best chain
    bool ActivateBestChain(BlockValidationState& state, 
                           const CChainParams& chainparams,
                           std::shared_ptr<const CBlock> pblock);
    
    // Connect/disconnect blocks
    bool ConnectBlock(const CBlock& block, BlockValidationState& state, 
                      CBlockIndex* pindex, CCoinsViewCache& view, 
                      const CChainParams& chainparams, bool fJustCheck = false);
    
    DisconnectResult DisconnectBlock(const CBlock& block, const CBlockIndex* pindex, 
                                     CCoinsViewCache& view);
    
    // Check if in initial block download
    bool IsInitialBlockDownload() const;
    
    // Check if MWEB is active
    bool IsMWEBActive() const;
};
```

**Usage Example:**
```cpp
// Get active chain state
CChainState& chainstate = ChainstateActive();

// Check if in IBD
if (chainstate.IsInitialBlockDownload()) {
    // Still downloading blocks
}

// Check MWEB status
if (chainstate.IsMWEBActive()) {
    // MWEB features are available
}

// Get UTXO view
CCoinsViewCache& view = chainstate.CoinsTip();
```

#### ChainstateManager Class

Manages multiple chainstates (IBD and snapshot):

```cpp
class ChainstateManager {
public:
    // Get active chainstate
    CChainState& ActiveChainstate() const;
    CChain& ActiveChain() const;
    int ActiveHeight() const;
    CBlockIndex* ActiveTip() const;
    
    // Process new block
    bool ProcessNewBlock(const CChainParams& chainparams, 
                         const std::shared_ptr<const CBlock> pblock, 
                         bool fForceProcessing, bool* fNewBlock);
    
    // Process block headers
    bool ProcessNewBlockHeaders(const std::vector<CBlockHeader>& block, 
                                BlockValidationState& state, 
                                const CChainParams& chainparams, 
                                const CBlockIndex** ppindex = nullptr);
    
    // Check if snapshot is active
    bool IsSnapshotActive() const;
    
    // Get validated chainstate
    CChainState& ValidatedChainstate() const;
};
```

**Usage Example:**
```cpp
// Get chainstate manager
ChainstateManager& chainman = g_chainman;

// Process a new block
std::shared_ptr<const CBlock> pblock = std::make_shared<const CBlock>(block);
bool fNewBlock = false;
if (chainman.ProcessNewBlock(Params(), pblock, false, &fNewBlock)) {
    if (fNewBlock) {
        // Block was new to us
    }
}

// Get current chain height
int height = chainman.ActiveHeight();
CBlockIndex* tip = chainman.ActiveTip();
```

---

## RPC APIs

The RPC (Remote Procedure Call) system provides external access to Zorkcoin functionality.

### RPC Server Management

```cpp
// RPC server control
void StartRPC();
void InterruptRPC();
void StopRPC();

// RPC status
bool IsRPCRunning();
void RpcInterruptionPoint();

// Warmup control
void SetRPCWarmupStatus(const std::string& newStatus);
void SetRPCWarmupFinished();
bool RPCIsInWarmup(std::string *outStatus);
```

### RPC Command System

```cpp
class CRPCCommand {
public:
    std::string category;
    std::string name;
    Actor actor;
    std::vector<std::string> argNames;
    intptr_t unique_id;
};

class CRPCTable {
public:
    // Execute RPC command
    UniValue execute(const JSONRPCRequest &request) const;
    
    // Get help for command
    std::string help(const std::string& name, const JSONRPCRequest& helpreq) const;
    
    // List all commands
    std::vector<std::string> listCommands() const;
    
    // Add/remove commands
    void appendCommand(const std::string& name, const CRPCCommand* pcmd);
    bool removeCommand(const std::string& name, const CRPCCommand* pcmd);
};
```

**Usage Example:**
```cpp
// Execute RPC command
JSONRPCRequest request;
request.strMethod = "getblockchaininfo";
request.params = UniValue(UniValue::VARR);

CRPCTable table;
UniValue result = table.execute(request);

// Get help for a command
std::string help = table.help("getblockchaininfo", request);
```

### Common RPC Commands

The following are some of the most commonly used RPC commands:

#### Blockchain Commands
- `getblockchaininfo` - Get blockchain information
- `getblock` - Get block by hash or height
- `getblockhash` - Get block hash by height
- `getbestblockhash` - Get best block hash
- `getblockcount` - Get current block count
- `getdifficulty` - Get current difficulty
- `getchaintips` - Get chain tips

#### Transaction Commands
- `getrawtransaction` - Get raw transaction
- `decoderawtransaction` - Decode raw transaction
- `sendrawtransaction` - Send raw transaction
- `gettxout` - Get transaction output
- `gettxoutproof` - Get transaction proof

#### Wallet Commands
- `getbalance` - Get wallet balance
- `sendtoaddress` - Send to address
- `listtransactions` - List transactions
- `getnewaddress` - Get new address
- `importaddress` - Import address

**Usage Example:**
```bash
# Get blockchain info
zorkcoin-cli getblockchaininfo

# Get block by height
zorkcoin-cli getblock 100000

# Send transaction
zorkcoin-cli sendtoaddress "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" 0.001

# Get wallet balance
zorkcoin-cli getbalance
```

---

## Wallet APIs

The wallet system provides comprehensive transaction and key management functionality.

### Core Wallet Functions

```cpp
// Wallet management
bool AddWallet(const std::shared_ptr<CWallet>& wallet);
bool RemoveWallet(const std::shared_ptr<CWallet>& wallet, 
                  Optional<bool> load_on_start, 
                  std::vector<bilingual_str>& warnings);
std::vector<std::shared_ptr<CWallet>> GetWallets();
std::shared_ptr<CWallet> GetWallet(const std::string& name);

// Wallet creation and loading
std::shared_ptr<CWallet> LoadWallet(interfaces::Chain& chain, 
                                    const std::string& name, 
                                    Optional<bool> load_on_start, 
                                    const DatabaseOptions& options, 
                                    DatabaseStatus& status, 
                                    bilingual_str& error, 
                                    std::vector<bilingual_str>& warnings);

std::shared_ptr<CWallet> CreateWallet(interfaces::Chain& chain, 
                                      const std::string& name, 
                                      Optional<bool> load_on_start, 
                                      DatabaseOptions& options, 
                                      DatabaseStatus& status, 
                                      bilingual_str& error, 
                                      std::vector<bilingual_str>& warnings);
```

### CWallet Class

The main wallet class provides transaction and key management:

```cpp
class CWallet {
public:
    // Transaction management
    bool CreateTransaction(const std::vector<CRecipient>& recipients, 
                           CTransactionRef& tx, CAmount& nFeeRet, 
                           int& nChangePosInOut, bilingual_str& error, 
                           const CCoinControl& coin_control = CCoinControl());
    
    bool CommitTransaction(CTransactionRef tx, CWalletTx& wtxNew, 
                           CReserveKey& reservekey, 
                           bilingual_str& error);
    
    // Address management
    CPubKey GenerateNewKey(WalletBatch& batch, bool internal = false);
    CTxDestination GetNewDestination(OutputType type, const std::string& label);
    
    // Balance and UTXO
    CAmount GetBalance(const isminefilter& filter = ISMINE_SPENDABLE, 
                       const int min_depth = 0) const;
    std::vector<COutput> AvailableCoins(const CCoinControl& coin_control = CCoinControl()) const;
    
    // Signing
    bool SignTransaction(CMutableTransaction& tx);
    bool SignMessage(const std::string& message, const std::string& message_magic, 
                     const CTxDestination& address, std::string& signature) const;
    
    // MWEB support
    bool CreateMWEBTransaction(const std::vector<CRecipient>& recipients, 
                               CTransactionRef& tx, CAmount& nFeeRet, 
                               bilingual_str& error);
};
```

**Usage Example:**
```cpp
// Get wallet
std::shared_ptr<CWallet> wallet = GetWallet("default");

// Get balance
CAmount balance = wallet->GetBalance();

// Create new address
CTxDestination dest = wallet->GetNewDestination(OutputType::BECH32, "My Address");

// Create transaction
std::vector<CRecipient> recipients;
recipients.push_back({dest, 100000, false}); // 0.001 ZRK

CTransactionRef tx;
CAmount nFeeRet;
int nChangePosInOut;
bilingual_str error;

if (wallet->CreateTransaction(recipients, tx, nFeeRet, nChangePosInOut, error)) {
    // Transaction created successfully
    CWalletTx wtxNew;
    CReserveKey reservekey(wallet.get());
    if (wallet->CommitTransaction(tx, wtxNew, reservekey, error)) {
        // Transaction committed to wallet
    }
}
```

### MWEB Wallet Support

Zorkcoin includes MWEB (Mimblewimble Extension Blocks) support:

```cpp
// MWEB wallet functions
bool CreateMWEBTransaction(const std::vector<CRecipient>& recipients, 
                           CTransactionRef& tx, CAmount& nFeeRet, 
                           bilingual_str& error);

// MWEB address generation
CTxDestination GetNewMWEBAddress(const std::string& label);

// MWEB balance
CAmount GetMWEBBalance() const;
```

---

## Network APIs

The networking system handles peer-to-peer communication and connection management.

### Connection Management

```cpp
// Connection limits
static const unsigned int DEFAULT_MAX_PEER_CONNECTIONS = 125;
static const int MAX_OUTBOUND_FULL_RELAY_CONNECTIONS = 8;
static const int MAX_ADDNODE_CONNECTIONS = 8;
static const int MAX_BLOCK_RELAY_ONLY_CONNECTIONS = 2;
static const int MAX_FEELER_CONNECTIONS = 1;

// Timeout settings
static const int TIMEOUT_INTERVAL = 20 * 60;
static const int FEELER_INTERVAL = 120;
static const int64_t DEFAULT_PEER_CONNECT_TIMEOUT = 60;
```

### CConnman Class

The connection manager handles all network connections:

```cpp
class CConnman {
public:
    // Start/stop networking
    bool Start(CScheduler& scheduler, const Options& connOptions);
    void Stop();
    
    // Connection management
    void OpenNetworkConnection(const CAddress& addrConnect, 
                               bool fCountFailure, 
                               ConnectionType conn_type = ConnectionType::OUTBOUND_FULL_RELAY);
    
    void CloseNode(NodeId id);
    
    // Address management
    void AddOneShot(const std::string& strDest);
    void AddNode(const std::string& strNode);
    void RemoveAddedNode(const std::string& strNode);
    
    // Peer information
    std::vector<CNodeStats> GetNodeStats(int64_t& nBestBlockTime, 
                                         int64_t& nBestBlockHeight);
    
    // Message handling
    void PushMessage(CNode* pnode, CSerializedNetMsg&& msg);
    
    // Ban management
    void Ban(const CNetAddr& netAddr, const BanReason& reason, 
             int64_t banTimeOffset = 0, bool sinceUnixEpoch = false);
    bool IsBanned(const CNetAddr& netAddr);
    void ClearBanned();
};
```

**Usage Example:**
```cpp
// Get connection manager
CConnman& connman = g_connman;

// Add a node
connman.AddNode("192.168.1.100:8333");

// Get peer statistics
int64_t nBestBlockTime, nBestBlockHeight;
std::vector<CNodeStats> vstats = connman.GetNodeStats(nBestBlockTime, nBestBlockHeight);

// Send message to peer
CSerializedNetMsg msg;
// ... populate message
connman.PushMessage(pnode, std::move(msg));
```

### Message Handling

```cpp
// Message types
enum NetMsgType {
    MSG_TX = 1,
    MSG_BLOCK = 2,
    MSG_FILTERED_BLOCK = 3,
    MSG_CMPCT_BLOCK = 4,
    MSG_WITNESS_BLOCK = 5,
    MSG_WITNESS_TX = 6,
    MSG_MWEB_BLOCK = 7,  // MWEB specific
    MSG_MWEB_TX = 8,     // MWEB specific
};

// Message handling
class CNode {
public:
    // Send message
    void PushMessage(const CSerializedNetMsg& msg);
    
    // Receive message
    bool ReceiveMsgBytes(const char* pch, unsigned int nBytes, bool& complete);
    
    // Message handlers
    bool ProcessMessages();
    void SendMessages();
};
```

---

## Cryptographic APIs

### Hash Functions

```cpp
// SHA-256 hashing
class CSHA256 {
public:
    static const size_t OUTPUT_SIZE = 32;
    
    CSHA256();
    CSHA256& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CSHA256& Reset();
};

// Double SHA-256
void SHA256D64(unsigned char* output, const unsigned char* input, size_t blocks);

// Auto-detect best implementation
std::string SHA256AutoDetect();
```

**Usage Example:**
```cpp
#include <crypto/sha256.h>

// Single SHA-256
CSHA256 hasher;
hasher.Write(data, data_len);
unsigned char hash[CSHA256::OUTPUT_SIZE];
hasher.Finalize(hash);

// Double SHA-256
unsigned char double_hash[32];
SHA256D64(double_hash, data, 1);
```

### Key Management

```cpp
// Public key operations
class CPubKey {
public:
    bool IsValid() const;
    bool IsCompressed() const;
    bool IsFullyValid() const;
    bool Decompress();
    
    // Hash operations
    uint160 GetID() const;
    uint256 GetHash() const;
    
    // Signature verification
    bool Verify(const uint256& hash, const std::vector<unsigned char>& vchSig) const;
};

// Private key operations
class CKey {
public:
    bool IsValid() const;
    bool IsCompressed() const;
    
    // Key generation
    void MakeNewKey(bool fCompressed);
    
    // Signing
    bool Sign(const uint256& hash, std::vector<unsigned char>& vchSig, 
              uint32_t test_case = 0) const;
    
    // Public key derivation
    CPubKey GetPubKey() const;
};
```

**Usage Example:**
```cpp
#include <key.h>

// Generate new key pair
CKey key;
key.MakeNewKey(true); // compressed
CPubKey pubkey = key.GetPubKey();

// Sign message
uint256 hash = Hash(message);
std::vector<unsigned char> signature;
if (key.Sign(hash, signature)) {
    // Signature created
}

// Verify signature
if (pubkey.Verify(hash, signature)) {
    // Signature is valid
}
```

---

## Qt GUI APIs

The Qt GUI provides a comprehensive user interface for Zorkcoin.

### Main Application

```cpp
// Main application class
class BitcoinApplication : public QApplication {
public:
    BitcoinApplication(int& argc, char** argv);
    ~BitcoinApplication();
    
    // Wallet management
    void createWallet(interfaces::Chain& chain, const std::string& name);
    void removeWallet(const std::string& name);
    
    // Window management
    void createWindow(const NetworkStyle* networkStyle);
    void shutdown();
};
```

### Main Window

```cpp
// Main window class
class BitcoinGUI : public QMainWindow {
public:
    // Wallet operations
    void setWalletController(WalletController* wallet_controller);
    
    // UI updates
    void setClientModel(ClientModel* clientModel);
    void setWalletModel(WalletModel* walletModel);
    
    // Menu actions
    void gotoOverviewPage();
    void gotoSendCoinsPage();
    void gotoReceiveCoinsPage();
    void gotoHistoryPage();
    void gotoMiningPage();
    
    // Notifications
    void message(const QString& title, const QString& message, 
                 unsigned int style, bool* ret = nullptr);
};
```

### Wallet Models

```cpp
// Wallet model for data binding
class WalletModel : public QObject {
public:
    // Balance operations
    CAmount getBalance(const CCoinControl* coinControl = nullptr) const;
    CAmount getUnconfirmedBalance() const;
    CAmount getImmatureBalance() const;
    
    // Transaction operations
    bool sendCoins(WalletModelTransaction& transaction);
    bool prepareTransaction(WalletModelTransaction& transaction, 
                           const CCoinControl& coinControl);
    
    // Address operations
    QString getAddressTableModel() const;
    QString getTransactionTableModel() const;
    
    // Encryption
    bool setWalletEncrypted(bool encrypted, const SecureString& passphrase);
    bool changePassphrase(const SecureString& oldPass, 
                          const SecureString& newPass);
};
```

**Usage Example:**
```cpp
// In a Qt widget
WalletModel* walletModel = getWalletModel();

// Get balance
CAmount balance = walletModel->getBalance();
QString balanceText = BitcoinUnits::format(walletModel->getOptionsModel()->getDisplayUnit(), balance);

// Send coins
WalletModelTransaction transaction;
// ... populate transaction
if (walletModel->sendCoins(transaction)) {
    // Transaction sent successfully
}
```

---

## Utility APIs

### System Utilities

```cpp
// File system operations
bool FileCommit(FILE *file);
bool TruncateFile(FILE *file, unsigned int length);
bool RenameOver(fs::path src, fs::path dest);
bool LockDirectory(const fs::path& directory, const std::string lockfile_name, 
                   bool probe_only=false);
void UnlockDirectory(const fs::path& directory, const std::string& lockfile_name);

// Directory operations
bool DirIsWritable(const fs::path& directory);
bool CheckDiskSpace(const fs::path& dir, uint64_t additional_bytes = 0);
bool TryCreateDirectories(const fs::path& p);

// Path utilities
fs::path GetDefaultDataDir();
const fs::path &GetBlocksDir();
const fs::path &GetDataDir(bool fNetSpecific = true);
fs::path GetConfigFile(const std::string& confPath);
```

### Amount Utilities

```cpp
// Amount constants
static const CAmount COIN = 100000000;
static const CAmount MAX_MONEY = 84000000 * COIN;

// Amount validation
inline bool MoneyRange(const CAmount& nValue) { 
    return (nValue >= 0 && nValue <= MAX_MONEY); 
}

// Amount formatting
std::string FormatMoney(CAmount n, bool fPlus = false);
bool ParseMoney(const std::string& str, CAmount& nRet);
```

**Usage Example:**
```cpp
#include <amount.h>
#include <util/moneystr.h>

// Create amount
CAmount amount = 100000000; // 1 ZRK in satoshis

// Validate amount
if (MoneyRange(amount)) {
    // Amount is valid
}

// Format amount
std::string formatted = FormatMoney(amount); // "1.00000000"

// Parse amount
CAmount parsed;
if (ParseMoney("1.5", parsed)) {
    // parsed = 150000000 satoshis
}
```

### Logging

```cpp
// Log levels
enum LogLevel {
    BCLog::NONE = 0,
    BCLog::ERROR = 1,
    BCLog::WARNING = 2,
    BCLog::INFO = 3,
    BCLog::DEBUG = 4,
    BCLog::TRACE = 5
};

// Logging functions
void LogPrintf(const char* fmt, ...);
void LogPrint(const LogLevel& level, const char* fmt, ...);
void LogPrintfCategory(const LogCategory& category, const char* fmt, ...);
```

**Usage Example:**
```cpp
#include <logging.h>

// Basic logging
LogPrintf("Processing block %s\n", block.GetHash().ToString());

// Categorized logging
LogPrintfCategory(BCLog::NET, "Received block %s from peer %d\n", 
                  block.GetHash().ToString(), nodeid);

// Conditional logging
if (LogAcceptCategory(BCLog::VALIDATION)) {
    LogPrintf("Block validation details...\n");
}
```

---

## Examples and Usage

### Complete Example: Creating and Broadcasting a Transaction

```cpp
#include <wallet/wallet.h>
#include <validation.h>
#include <net.h>

// Get wallet
std::shared_ptr<CWallet> wallet = GetWallet("default");
if (!wallet) {
    throw std::runtime_error("Wallet not found");
}

// Create transaction
std::vector<CRecipient> recipients;
CTxDestination dest = wallet->GetNewDestination(OutputType::BECH32, "Test");
recipients.push_back({dest, 100000, false}); // 0.001 ZRK

CTransactionRef tx;
CAmount nFeeRet;
int nChangePosInOut;
bilingual_str error;

if (!wallet->CreateTransaction(recipients, tx, nFeeRet, nChangePosInOut, error)) {
    throw std::runtime_error("Failed to create transaction: " + error.original);
}

// Commit to wallet
CWalletTx wtxNew;
CReserveKey reservekey(wallet.get());
if (!wallet->CommitTransaction(tx, wtxNew, reservekey, error)) {
    throw std::runtime_error("Failed to commit transaction: " + error.original);
}

// Broadcast transaction
CConnman& connman = g_connman;
CInv inv(MSG_TX, tx->GetHash());
connman.ForEachNode([&inv](CNode* pnode) {
    pnode->PushInventory(inv);
});
```

### Example: Block Validation

```cpp
#include <validation.h>
#include <consensus/consensus.h>

bool ValidateBlock(const CBlock& block, const CBlockIndex* pindexPrev) {
    BlockValidationState state;
    const Consensus::Params& params = Params().GetConsensus();
    
    // Check basic block validity
    if (!CheckBlock(block, state, params)) {
        LogPrintf("Block validation failed: %s\n", state.ToString());
        return false;
    }
    
    // Check if witness is enabled
    if (IsWitnessEnabled(pindexPrev, params)) {
        // Additional witness validation
    }
    
    // Check if MWEB is enabled
    if (IsMWEBEnabled(pindexPrev, params)) {
        // Additional MWEB validation
    }
    
    return true;
}
```

### Example: RPC Command Implementation

```cpp
#include <rpc/server.h>

static RPCHelpMan getblockinfo() {
    return RPCHelpMan{
        "getblockinfo",
        "Get detailed information about a block.\n",
        {
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hash", "The block hash"},
                {RPCResult::Type::NUM, "height", "The block height"},
                {RPCResult::Type::NUM, "time", "The block time"},
                {RPCResult::Type::NUM, "size", "The block size"},
            }
        },
        RPCExamples{
            HelpExampleCli("getblockinfo", "\"0000000000000000000000000000000000000000000000000000000000000000\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            uint256 blockHash = ParseHashV(request.params[0], "blockhash");
            
            LOCK(cs_main);
            CBlockIndex* pblockindex = LookupBlockIndex(blockHash);
            if (!pblockindex) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
            }
            
            UniValue result(UniValue::VOBJ);
            result.pushKV("hash", pblockindex->GetBlockHash().GetHex());
            result.pushKV("height", pblockindex->nHeight);
            result.pushKV("time", (int64_t)pblockindex->nTime);
            result.pushKV("size", (int64_t)pblockindex->nSize);
            
            return result;
        }
    };
}
```

---

## Conclusion

This documentation provides comprehensive coverage of the Zorkcoin API surface. The codebase includes all the standard Bitcoin Core functionality plus additional features like MWEB support and the kHeavyHash algorithm. 

For more specific implementation details, refer to the source code in the respective header files, and for usage examples, check the test files in the `src/test/` directory.

Key areas for developers to focus on:
1. **Consensus APIs** - For blockchain validation and consensus rules
2. **Validation APIs** - For block and transaction validation
3. **Wallet APIs** - For transaction creation and key management
4. **RPC APIs** - For external application integration
5. **Network APIs** - For peer-to-peer communication
6. **Qt APIs** - For GUI application development

The MWEB integration provides additional privacy features through Mimblewimble Extension Blocks, making Zorkcoin suitable for applications requiring enhanced transaction privacy.