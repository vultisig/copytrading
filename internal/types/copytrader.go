package types

import (
	"time"

	"github.com/google/uuid"
)

type CopytradingPair struct {
	PolicyID   uuid.UUID `db:"policy_id"`
	Resource   string    `db:"resource"`
	LeaderAddr string    `db:"leader_addr"`
	CreatedAt  time.Time `db:"created_at"`
	DeletedAt  time.Time `db:"deleted_at"`
}
