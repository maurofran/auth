package cmd

import (
	"github.com/maurofran/auth/internal/ports/adapters/oidc"
	"github.com/maurofran/kernel/db"
	"github.com/maurofran/kernel/logger"
	"github.com/maurofran/kernel/redis"
	"github.com/maurofran/kernel/server"
)

var config Config

// Config aggregates configuration settings for the database, Redis, server, and logging components.
type Config struct {
	DB     db.Config     `mapstructure:"db"`
	Redis  redis.Config  `mapstructure:"redis"`
	Server server.Config `mapstructure:"server"`
	Logger logger.Config `mapstructure:"logging"`
	Oidc   oidc.Config   `mapstructure:"oidc"`
}
