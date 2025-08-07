package storage

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	vtypes "github.com/vultisig/verifier/types"

	"github.com/vultisig/copytrading/internal/types"
)

type DatabaseStorage interface {
	Close() error

	GetPluginPolicy(ctx context.Context, id uuid.UUID) (*vtypes.PluginPolicy, error)
	GetAllPluginPolicies(ctx context.Context, publicKey string, pluginID vtypes.PluginID, onlyActive bool) ([]vtypes.PluginPolicy, error)
	DeletePluginPolicyTx(ctx context.Context, dbTx pgx.Tx, id uuid.UUID) error
	InsertPluginPolicyTx(ctx context.Context, dbTx pgx.Tx, policy vtypes.PluginPolicy) (*vtypes.PluginPolicy, error)
	UpdatePluginPolicyTx(ctx context.Context, dbTx pgx.Tx, policy vtypes.PluginPolicy) (*vtypes.PluginPolicy, error)

	InsertCopytradingPairTx(ctx context.Context, dbTx pgx.Tx, policyID uuid.UUID, resourse string, lead common.Address) error
	GetPoliciesByResourceAndLeader(ctx context.Context, resource string, lead common.Address) ([]types.CopytradingPair, error)
	DeleteWithTx(ctx context.Context, tx pgx.Tx, policyID uuid.UUID) error

	Pool() *pgxpool.Pool
}
