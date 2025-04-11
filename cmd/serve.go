package cmd

import (
	"github.com/spf13/cobra"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use: "serve",
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
