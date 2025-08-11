package postgres

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/vultisig/copytrading/internal/types"
)

func (p *PostgresBackend) InsertCopytradingPairsTx(
	ctx context.Context,
	dbTx pgx.Tx,
	pairs []types.CopytradingPair) error {
	batch := pgx.Batch{}
	for _, pair := range pairs {
		batch.Queue(
			`INSERT INTO copytrading_pair 
            (policy_id, resource, leader_addr) 
            VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
			pair.PolicyID,
			pair.Resource,
			pair.LeaderAddr,
		)
	}
	br := dbTx.SendBatch(ctx, &batch)
	defer br.Close()

	for range pairs {
		_, err := br.Exec()
		if err != nil {
			return fmt.Errorf("failed to create copytrading pair: %w", err)
		}
	}
	return nil
}

func (p *PostgresBackend) GetPoliciesByResourceAndLeader(
	ctx context.Context, resource string, lead common.Address) ([]types.CopytradingPair, error) {
	var pairs []types.CopytradingPair
	rows, err := p.pool.Query(ctx, `SELECT policy_id FROM copytrading_pair 
                                             WHERE resource = $1 AND leader_addr = $2 AND deleted_at IS NULL`, resource, lead.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query pairs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var pair types.CopytradingPair
		err := rows.Scan(
			&pair.PolicyID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan pair: %w", err)
		}
		pairs = append(pairs, pair)
	}
	return pairs, nil
}

func (p *PostgresBackend) DeletePairsWithTx(ctx context.Context, tx pgx.Tx, policyID uuid.UUID) error {
	_, err := tx.Exec(ctx, `
		UPDATE copytrading_pair SET deleted_at = now()
		WHERE policy_id = $1 AND deleted_at IS NULL
	`, policyID)
	if err != nil {
		return fmt.Errorf("failed to delete pair: %w", err)
	}
	return nil
}
