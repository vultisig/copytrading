package plugin

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

type WatcherQueue struct {
	Name string
	Task string
}

type SwapTask struct {
	Resource string
	Sender   common.Address
	Path     []common.Address
	Amount   *big.Int
}

type PolicySwapParams struct {
	Aim              string
	SourceToken      string
	DestinationToken string
	MinAmount        string
	MaxAmount        string
	Amount           string
}
