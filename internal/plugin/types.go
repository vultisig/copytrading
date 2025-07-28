package plugin

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

type SwapTask struct {
	Sender common.Address
	Path   []common.Address
	Amount *big.Int
}
