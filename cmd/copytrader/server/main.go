package main

import (
	"context"
	"fmt"
	"net"

	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/copytrading/internal/service"
	"github.com/vultisig/verifier/plugin/redis"
	"github.com/vultisig/verifier/plugin/server"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/storage"
	"github.com/vultisig/verifier/vault"

	"github.com/vultisig/copytrading/internal/plugin"
	"github.com/vultisig/copytrading/internal/storage/postgres"
)

func main() {
	ctx := context.Background()

	cfg, err := GetConfigure()
	if err != nil {
		panic(err)
	}
	logger := logrus.New()

	redisStorage, err := redis.NewRedis(cfg.Redis)
	if err != nil {
		panic(err)
	}
	redisOptions := asynq.RedisClientOpt{
		Addr:     net.JoinHostPort(cfg.Redis.Host, cfg.Redis.Port),
		Username: cfg.Redis.User,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}

	client := asynq.NewClient(redisOptions)
	defer func() {
		if err := client.Close(); err != nil {
			fmt.Println("fail to close asynq client,", err)
		}
	}()

	inspector := asynq.NewInspector(redisOptions)

	vaultStorage, err := vault.NewBlockStorageImp(cfg.BlockStorage)
	if err != nil {
		panic(err)
	}

	db, err := postgres.NewPostgresBackend(cfg.Database.DSN, nil)
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
	}

	txIndexerStore, err := storage.NewPostgresTxIndexStore(ctx, cfg.Database.DSN)
	if err != nil {
		panic(fmt.Errorf("tx_indexer_storage.NewPostgresTxIndexStore: %w", err))
	}

	txIndexerService := tx_indexer.NewService(
		logger,
		txIndexerStore,
		tx_indexer.Chains(),
	)

	ct, err := plugin.NewPlugin(
		db,
		nil, // not used by server
		vaultStorage,
		nil,
		txIndexerService,
		client,
		cfg.Server.EncryptionSecret,
		nil,
	)
	if err != nil {
		logger.Fatalf("failed to create copytrader plugin,err: %s", err)
	}

	policyService, err := service.NewPolicyService(db, nil, logger)

	srv := server.NewServer(
		cfg.Server,
		policyService,
		redisStorage,
		vaultStorage,
		client,
		inspector,
		ct,
		server.DefaultMiddlewares(),
	)
	if err := srv.Start(ctx); err != nil {
		panic(err)
	}
}
