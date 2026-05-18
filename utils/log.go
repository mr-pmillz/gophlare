package utils

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"os"
	"runtime"
	"time"
)

// LogError logs `err` to stderr (via gologger) and, on a best-effort basis,
// appends it to a dated file in the CWD. The file write is non-fatal: if
// the open fails (e.g. read-only filesystem, common in containers), we skip
// the file tee and still log to stderr — and crucially still return the
// ORIGINAL `err`. Returning a filesystem error in place of the caller's
// real error has masked production failures.
func LogError(err error) error {
	timestamp := time.Now().Format("01-02-2006")
	fname := fmt.Sprintf("gophlare-error-log-%s.json", timestamp)

	pc, file, line, ok := runtime.Caller(1)
	if !ok {
		LogWarningf("Failed to retrieve Caller information")
	}
	fn := runtime.FuncForPC(pc).Name()

	f, openFileErr := os.OpenFile(fname, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if openFileErr == nil {
		defer f.Close()
		teeFormatter := formatter.NewTee(formatter.NewCLI(false), f)
		gologger.DefaultLogger.SetFormatter(teeFormatter)
	}
	gologger.DefaultLogger.SetMaxLevel(levels.LevelError)
	gologger.Error().Msgf("Error in function %s, called from %s:%d:\n %v", fn, file, line, err)
	return err
}

// LogWarningf logs a warning to stdout
func LogWarningf(format string, args ...interface{}) {
	msgColor := color.New(color.FgHiYellow)
	emoji := "⚠️ " // Warning
	msg := fmt.Sprintf(format, args...)
	msgColor.EnableColor()
	msgStyle := msgColor.Sprintf("%s %s", emoji, msg) //nolint:govet
	gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	gologger.Warning().Label("WARN").Msgf("%s", msgStyle) //nolint:govet
}

// LogFatalf is a wrapper around gologger Fatal method
func LogFatalf(format string, args ...interface{}) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelFatal)
	gologger.Fatal().Msgf(format, args...)
}

// InfoLabelf ...
func InfoLabelf(label, format string, args ...interface{}) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	gologger.Info().Label(label).Msgf(format, args...)
}

// InfoLabelWithColorf logs a message to stdout with the format msg color.
// color choices are green red yellow and defaults to blue
func InfoLabelWithColorf(label, colorString, format string, args ...interface{}) {
	var msgColor *color.Color
	var emoji string
	switch {
	case colorString == "green":
		msgColor = color.New(color.FgHiGreen)
		emoji = "✅" // Success
	case colorString == "red":
		msgColor = color.New(color.FgHiRed)
		emoji = "❌" // Error
	case colorString == "yellow":
		msgColor = color.New(color.FgHiYellow)
		emoji = "⚠️ " // Warning
	case colorString == "magenta":
		msgColor = color.New(color.FgHiMagenta)
		emoji = "✨" // Highlight
	case colorString == "cyan":
		msgColor = color.New(color.FgCyan)
		emoji = "🗻" // bhis mountain
	default:
		msgColor = color.New(color.FgHiBlue)
		emoji = "ℹ️ " // Default info
	}
	msg := fmt.Sprintf(format, args...)
	msgColor.EnableColor()
	// Combine emoji with colored message
	msgStyle := msgColor.Sprintf("%s %s", emoji, msg) //nolint:govet
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	gologger.Info().Label(label).Msgf("%s", msgStyle) //nolint:govet
}
