package iovationsnarego

import (
	"fmt"
	"time"
)

type LogType string

const (
	LogInfo  LogType = "INFO"
	LogError LogType = "ERR "
	LogDebug LogType = "DBG "
)

func (g *BlackboxGenerator) log(logType LogType, message string) {
	fmt.Printf("[IOBLACKBOX] [%s] %s - %s\n", logType, time.Now().Format("2006-01-02T15:04:05.000"), message)
}

func (g *BlackboxGenerator) verboseLog(logType LogType, message string) {
	if g.Verbose {
		g.log(logType, message)
	}
}

func (g *BlackboxGenerator) debugLog(message string) {
	if g.Debug {
		g.log(LogDebug, message)
	}
}
