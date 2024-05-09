package nop

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const Version = "0.1.1"

var rootCmd = &cobra.Command{
	Use:     "nop",
	Version: Version,
	Short:   "NopFault - swiss army knife",
	Long: `
	this nop version has features:
		* fuzz - simple web fuzzer.
	`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "\n\n")
		os.Exit(1)
	}
}
