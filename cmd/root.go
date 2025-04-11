package cmd

import (
	"errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log/slog"
	"os"
	"strings"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authentication Server",
	Long:  `Authentication Server is a service that manages authentication and authorization using OAuth 2.0 and OpenID Connect.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		slog.SetLogLoggerLevel(config.Logger.SlogLevel())
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is .env)")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	v := viper.NewWithOptions(viper.KeyDelimiter("_"),
		viper.EnvKeyReplacer(strings.NewReplacer(".", "_")))
	if cfgFile != "" {
		// Use config file from the flag.
		v.SetConfigFile(cfgFile)
	} else {
		// Search config in home directory with name ".github.com/maurofran/iam" (without extension).
		v.AddConfigPath(".")
		v.AddConfigPath("./config")
		v.AddConfigPath("$HOME/.config/iam")

		v.SetConfigType("env")

		v.SetConfigName(".env")
		v.SetConfigName(".env.local")
	}

	v.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := v.ReadInConfig(); err == nil {
		slog.Info("Using config file", slog.String("file", viper.ConfigFileUsed()))
		if err := v.Unmarshal(&config); err != nil {
			slog.Error("Unable to parse config file", slog.Any("err", err))
		}
	} else {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
			slog.Debug("No config file found")
		} else {
			slog.Error("Error reading config file", slog.Any("err", err))
		}
	}
}
