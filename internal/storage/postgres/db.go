package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/verifier/plugin"

	"github.com/vultisig/copytrading/internal/storage"
)

var _ storage.DatabaseStorage = (*PostgresBackend)(nil)

type PostgresBackend struct {
	logger *logrus.Logger
	pool   *pgxpool.Pool
}

type MigrationOptions struct {
	RunSystemMigrations bool
	RunPluginMigrations bool
}

func NewPostgresBackend(logger *logrus.Logger, dsn string, opts *MigrationOptions) (*PostgresBackend, error) {
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	backend := &PostgresBackend{
		logger: logger,
		pool:   pool,
	}

	// Apply default options if not provided
	if opts == nil {
		opts = &MigrationOptions{
			RunSystemMigrations: true,
			RunPluginMigrations: true,
		}
	}

	if err := backend.Migrate(opts); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return backend, nil
}

func (p *PostgresBackend) Close() error {
	p.pool.Close()

	return nil
}

func (p *PostgresBackend) Migrate(opts *MigrationOptions) error {
	logrus.Info("Starting database migration...")

	// Run system migrations first (plugin_policies table)
	if opts.RunSystemMigrations {
		policyMgr := plugin.NewMigrationManager(p.logger, p.pool, "policy/policy_pg/migrations")
		if err := policyMgr.Migrate(); err != nil {
			return fmt.Errorf("failed to run policy migrations: %w", err)
		}
		txIndexerMgr := plugin.NewMigrationManager(p.logger, p.pool, "tx_indexer/pkg/storage/migrations")
		if err := txIndexerMgr.Migrate(); err != nil {
			return fmt.Errorf("failed to run txIndexer migrations: %w", err)
		}
	}

	// Run plugin migrations (all other tables)
	if opts.RunPluginMigrations {
		pluginMgr := NewPluginMigrationManager(p.pool)
		if err := pluginMgr.Migrate(); err != nil {
			return fmt.Errorf("failed to run plugin migrations: %w", err)
		}
	}

	logrus.Info("Database migration completed successfully")
	return nil
}

func (p *PostgresBackend) Pool() *pgxpool.Pool {
	return p.pool
}
