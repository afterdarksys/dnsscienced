package logging

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetQueryLogEnabled_EnablesWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Level:          LevelInfo,
		Format:         "console",
		OutputPath:     "stdout",
		EnableQueryLog: false,
		QueryLogPath:   filepath.Join(dir, "queries.log"),
		QueryLogFormat: "json",
	}
	l, err := NewLogger(cfg)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	if err := l.SetQueryLogEnabled(true); err != nil {
		t.Fatalf("SetQueryLogEnabled(true): %v", err)
	}
	if !l.IsQueryLogEnabled() {
		t.Error("expected IsQueryLogEnabled() = true after enable")
	}
	// File must exist
	if _, err := os.Stat(cfg.QueryLogPath); err != nil {
		t.Errorf("query log file not created: %v", err)
	}
}

func TestSetQueryLogEnabled_DisablesWhenEnabled(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Level:          LevelInfo,
		Format:         "console",
		OutputPath:     "stdout",
		EnableQueryLog: true,
		QueryLogPath:   filepath.Join(dir, "queries.log"),
		QueryLogFormat: "json",
	}
	l, err := NewLogger(cfg)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	if err := l.SetQueryLogEnabled(false); err != nil {
		t.Fatalf("SetQueryLogEnabled(false): %v", err)
	}
	if l.IsQueryLogEnabled() {
		t.Error("expected IsQueryLogEnabled() = false after disable")
	}
}

func TestSetQueryLogEnabled_NoopWhenAlreadyEnabled(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Level:          LevelInfo,
		Format:         "console",
		OutputPath:     "stdout",
		EnableQueryLog: true,
		QueryLogPath:   filepath.Join(dir, "queries.log"),
		QueryLogFormat: "json",
	}
	l, err := NewLogger(cfg)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	// Second enable should be no-op
	if err := l.SetQueryLogEnabled(true); err != nil {
		t.Fatalf("second SetQueryLogEnabled(true): %v", err)
	}
	if !l.IsQueryLogEnabled() {
		t.Error("expected IsQueryLogEnabled() = true after second enable")
	}
}

func TestQueryLogConfig(t *testing.T) {
	cfg := Config{
		Level:          LevelInfo,
		Format:         "console",
		OutputPath:     "stdout",
		EnableQueryLog: false,
		QueryLogPath:   "/tmp/test-queries.log",
		QueryLogFormat: "json",
	}
	l, err := NewLogger(cfg)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	path, format := l.QueryLogConfig()
	if path != cfg.QueryLogPath {
		t.Errorf("QueryLogConfig path = %q, want %q", path, cfg.QueryLogPath)
	}
	if format != cfg.QueryLogFormat {
		t.Errorf("QueryLogConfig format = %q, want %q", format, cfg.QueryLogFormat)
	}
}

func TestQueriesLogged_IncrementedByLogQuery(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Level:          LevelInfo,
		Format:         "console",
		OutputPath:     "stdout",
		EnableQueryLog: true,
		QueryLogPath:   filepath.Join(dir, "queries.log"),
		QueryLogFormat: "json",
	}
	l, err := NewLogger(cfg)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	if c := l.QueriesLogged(); c != 0 {
		t.Errorf("initial QueriesLogged = %d, want 0", c)
	}

	l.LogQuery(QueryLogEntry{Protocol: "udp"})
	l.LogQuery(QueryLogEntry{Protocol: "tcp"})

	if c := l.QueriesLogged(); c != 2 {
		t.Errorf("QueriesLogged after 2 LogQuery calls = %d, want 2", c)
	}
}

func TestQueriesLogged_NotIncrementedWhenDisabled(t *testing.T) {
	cfg := Config{
		Level:          LevelInfo,
		Format:         "console",
		OutputPath:     "stdout",
		EnableQueryLog: false,
	}
	l, err := NewLogger(cfg)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	l.LogQuery(QueryLogEntry{Protocol: "udp"})

	if c := l.QueriesLogged(); c != 0 {
		t.Errorf("QueriesLogged with disabled log = %d, want 0", c)
	}
}
