package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	ctx := context.Background()

	ethClient, err := ethclient.Dial("https://ethereum-rpc.publicnode.com")
	if err != nil {
		log.Fatal("failed to connect to eth client")
	}

	privateKey, err := crypto.HexToECDSA(pk)
	if err != nil {
		log.Fatal("failed to parse private key")
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	nonce, err := ethClient.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		log.Fatal("failed to get pending nonce")
	}

	gasPrice, err := ethClient.SuggestGasPrice(ctx)
	if err != nil {
		log.Fatal("failed to get gas price")
	}

	chainID, err := ethClient.ChainID(ctx)
	if err != nil {
		log.Fatal("failed to get chain ID")
	}

	signer := types.LatestSignerForChainID(chainID)
	transactOpts := &bind.TransactOpts{
		From: fromAddress,
		Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if address != fromAddress {
				return nil, errors.New("not authorized to sign this transaction")
			}
			signature, err := crypto.Sign(signer.Hash(tx).Bytes(), privateKey)
			if err != nil {
				log.Println(err)
				return nil, err
			}
			return tx.WithSignature(signer, signature)
		},
		Nonce:    big.NewInt(int64(nonce)),
		GasPrice: gasPrice,
		GasLimit: 1000000,
		Context:  ctx,
	}

	router, err := NewRouter(common.HexToAddress("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"), ethClient)
	if err != nil {
		log.Fatal(err)
	}
	deadline := new(big.Int).SetInt64(time.Now().Add(20 * time.Minute).Unix())

	tx, err := router.SwapExactTokensForTokens(
		transactOpts,
		big.NewInt(50000),
		big.NewInt(1),
		[]common.Address{common.HexToAddress("0xdAC17F958D2ee523a2206206994597C13D831ec7"), common.HexToAddress("0x8fc17671D853341D9e8B001F5Fc3C892d09CB53A")},
		fromAddress,
		deadline,
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Waiting to be mined...", tx.Hash().Hex())

	receipt, err := bind.WaitMined(ctx, ethClient, tx.Hash())
	if err != nil {
		log.Fatal("failed to wait tx: " + err.Error())
	}

	fmt.Println("tx hash: ", receipt.TxHash, receipt.BlockNumber.Int64())
}
