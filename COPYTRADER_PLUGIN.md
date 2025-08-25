# Vultisig Copytrader Plugin

## Overview

The Vultisig Copytrader Plugin is a specialized trading automation service that enables users to automatically replicate trades executed by other addresses on the Ethereum blockchain. The plugin monitors Uniswap V2 transactions in real-time and triggers corresponding trades based on predefined policies and user-configured parameters.

## Purpose

This plugin allows users to:
- **Follow successful traders**: Automatically copy trades from specific Ethereum addresses
- **Mirror trading strategies**: Replicate swap transactions with customizable parameters
- **Automate portfolio management**: Execute trades without manual intervention
- **Scale trading operations**: Handle multiple copy trading scenarios simultaneously

## Key Features

### 🔍 Real-time Transaction Monitoring
- Monitors Ethereum blockchain for Uniswap V2 Router transactions
- Processes blocks sequentially to ensure no trades are missed
- Filters transactions by specific method signatures (`swapExactTokensForTokens`)

### 🎯 Intelligent Trade Replication
- Extracts swap parameters from monitored transactions
- Supports configurable trade amounts and token pairs
- Implements policy-based trade execution controls

### 🔐 Secure Key Management
- Uses Vultisig's reshare technology for secure transaction signing
- Integrates with the Verifier service for policy validation
- Maintains isolated vault storage for plugin operations

### ⚡ Asynchronous Processing
- Queue-based trade execution using Redis and Asynq
- Parallel processing of multiple copy trading opportunities
- Configurable retry mechanisms and error handling

## Architecture Components

### Core Services

#### 1. **Server Component** (`copytrader.server`)
- **Purpose**: Main API server handling plugin management and vault operations
- **Configuration**: `copytrader.server.example.json`
- **Key Features**:
  - Vault reshare operations
  - Policy management
  - Transaction signing coordination
  - Database and Redis connectivity

#### 2. **Worker Component** (`copytrader.worker`) 
- **Purpose**: Background service processing copy trading tasks
- **Configuration**: `copytrader.worker.example.json`
- **Key Features**:
  - Blockchain monitoring via RPC
  - Trade execution logic
  - Queue task processing
  - Verifier service integration

#### 3. **Transaction Indexer** (`tx_indexer`)
- **Purpose**: Indexes and tracks blockchain transactions
- **Configuration**: `tx_indexer.example.json`
- **Key Features**:
  - Multi-blockchain support (Bitcoin, Ethereum)
  - Concurrent transaction processing
  - Lost transaction recovery

### Infrastructure Dependencies

- **PostgreSQL**: Stores plugin policies, vault data, and transaction history
- **Redis**: Message queue for asynchronous task processing
- **MinIO**: Object storage for blockchain data and backups

## Technical Specifications

### Supported Blockchains
- **Ethereum**: Primary blockchain for copy trading operations
- **Bitcoin**: Supported via transaction indexer (future expansion)

### Smart Contract Integration
- **Uniswap V2 Router**: `0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D`
- **Method Support**: `swapExactTokensForTokens` (`38ed1739`)

### Policy Configuration
```go
type PolicySwapParams struct {
    Aim              string // Trading objective/strategy
    SourceToken      string // Token to swap from
    DestinationToken string // Token to swap to  
    MinAmount        string // Minimum swap amount
    MaxAmount        string // Maximum swap amount
    Amount           string // Fixed swap amount
}
```

## Deployment

### Setup Steps
1. Clone the repository
2. Configure environment files from examples
3. Create shared Docker network: `docker network create shared-network`
4. Start services: `make up`

### Configuration Files
- `copytrader.server.example.json` - Server configuration template
- `copytrader.worker.example.json` - Worker configuration template  
- `tx_indexer.example.json` - Transaction indexer settings
- `docker-compose.yaml` - Service orchestration

## Security Features

### Policy Enforcement
- All trades must comply with user-signed policies
- Transaction validation through Verifier service
- Rate limiting and maximum transaction controls

### Key Management
- Utilizes Vultisig's threshold signature scheme (TSS)
- Reshare-based key isolation for plugin operations
- Secure vault storage with encryption

## Use Cases

### Individual Traders
- Copy trades from successful wallet addresses
- Implement stop-loss and take-profit strategies
- Automate DCA (Dollar Cost Averaging) strategies

### Fund Managers
- Replicate institutional trading strategies
- Scale trading operations across multiple accounts
- Implement risk management through policy controls
