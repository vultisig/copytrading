package storage

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vultisig/vultiserver/contexthelper"
)

// RedisConfig holds the configuration parameters for connecting to a Redis instance.
// Fields:
// - Host: The hostname or IP address of the Redis server.
// - Port: The port number on which the Redis server is listening.
// - User: The username for authentication (if required by the Redis server).
// - Password: The password for authentication (if required by the Redis server).
// - DB: The Redis database number to use (default is 0).
type RedisConfig struct {
	Host     string `mapstructure:"host" json:"host,omitempty"`
	Port     string `mapstructure:"port" json:"port,omitempty"`
	User     string `mapstructure:"user" json:"user,omitempty"`
	Password string `mapstructure:"password" json:"password,omitempty"`
	DB       int    `mapstructure:"db" json:"db,omitempty"`
}

type RedisStorage struct {
	cfg    RedisConfig
	client *redis.Client
}

func NewRedisStorage(cfg RedisConfig) (*RedisStorage, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Host + ":" + cfg.Port,
		Username: cfg.User,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	status := client.Ping(context.Background())
	if status.Err() != nil {
		return nil, status.Err()
	}
	return &RedisStorage{
		cfg:    cfg,
		client: client,
	}, nil
}

func (r *RedisStorage) Get(ctx context.Context, key string) (string, error) {
	if err := contexthelper.CheckCancellation(ctx); err != nil {
		return "", err
	}
	return r.client.Get(ctx, key).Result()
}
func (r *RedisStorage) Set(ctx context.Context, key string, value string, expiry time.Duration) error {
	if err := contexthelper.CheckCancellation(ctx); err != nil {
		return err
	}
	return r.client.Set(ctx, key, value, expiry).Err()
}
func (r *RedisStorage) Expire(ctx context.Context, key string, expiry time.Duration) error {
	if err := contexthelper.CheckCancellation(ctx); err != nil {
		return err
	}
	return r.client.Expire(ctx, key, expiry).Err()
}
func (r *RedisStorage) Delete(ctx context.Context, key string) error {
	if err := contexthelper.CheckCancellation(ctx); err != nil {
		return err
	}
	return r.client.Del(ctx, key).Err()
}
func (r *RedisStorage) Close() error {
	return r.client.Close()
}
