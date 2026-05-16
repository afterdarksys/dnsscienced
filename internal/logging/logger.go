package logging

import (
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// LogLevel represents the logging level
type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
)

// Config holds logging configuration
type Config struct {
	// System logging
	Level      LogLevel `yaml:"level"`
	Format     string   `yaml:"format"`      // "json" or "console"
	OutputPath string   `yaml:"output_path"` // File path or "stdout" or "stderr"
	Syslog     bool     `yaml:"syslog"`      // Enable syslog output
	SyslogAddr string   `yaml:"syslog_addr"` // Syslog server address (e.g., "localhost:514")

	// Query logging
	EnableQueryLog bool   `yaml:"enable_query_log"`
	QueryLogPath   string `yaml:"query_log_path"`
	QueryLogFormat string `yaml:"query_log_format"` // "json" or "text"
}

// DefaultConfig returns default logging configuration
func DefaultConfig() Config {
	return Config{
		Level:          LevelInfo,
		Format:         "console",
		OutputPath:     "stdout",
		Syslog:         false,
		EnableQueryLog: false,
		QueryLogPath:   "/var/log/dnsscienced/queries.log",
		QueryLogFormat: "json",
	}
}

// Logger wraps zerolog with DNS-specific functionality
type Logger struct {
	mu sync.Mutex

	systemLog zerolog.Logger
	queryLog  zerolog.Logger

	config Config

	// Query log file handle
	queryFile *os.File

	// queriesLogged counts queries logged since startup (atomic, no lock needed)
	queriesLogged atomic.Int64
}

// NewWithWriter creates a Logger that writes structured JSON to w.
// Intended for tests that need to capture log output via bytes.Buffer.
func NewWithWriter(w io.Writer) *Logger {
	l := &Logger{}
	l.systemLog = zerolog.New(w).With().Timestamp().Logger()
	return l
}

// NewLogger creates a new Logger instance
func NewLogger(cfg Config) (*Logger, error) {
	l := &Logger{
		config: cfg,
	}

	// Setup system logger
	if err := l.setupSystemLog(); err != nil {
		return nil, err
	}

	// Setup query logger if enabled
	if cfg.EnableQueryLog {
		if err := l.setupQueryLog(); err != nil {
			return nil, err
		}
	}

	return l, nil
}

// setupSystemLog configures the system logger
func (l *Logger) setupSystemLog() error {
	// Set log level
	level := zerolog.InfoLevel
	switch l.config.Level {
	case LevelDebug:
		level = zerolog.DebugLevel
	case LevelInfo:
		level = zerolog.InfoLevel
	case LevelWarn:
		level = zerolog.WarnLevel
	case LevelError:
		level = zerolog.ErrorLevel
	}
	zerolog.SetGlobalLevel(level)

	// Setup output writer
	var writer io.Writer

	switch l.config.OutputPath {
	case "stdout", "":
		writer = os.Stdout
	case "stderr":
		writer = os.Stderr
	default:
		// Open log file
		dir := filepath.Dir(l.config.OutputPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}

		f, err := os.OpenFile(l.config.OutputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return err
		}
		writer = f
	}

	// Apply formatting
	if l.config.Format == "console" {
		writer = zerolog.ConsoleWriter{
			Out:        writer,
			TimeFormat: time.RFC3339,
			NoColor:    l.config.OutputPath != "stdout" && l.config.OutputPath != "stderr",
		}
	}

	// Create logger
	l.systemLog = zerolog.New(writer).With().Timestamp().Logger()

	// Set as global logger
	log.Logger = l.systemLog

	return nil
}

// setupQueryLog configures the query logger
func (l *Logger) setupQueryLog() error {
	// Create query log directory
	dir := filepath.Dir(l.config.QueryLogPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Open query log file
	f, err := os.OpenFile(l.config.QueryLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	l.queryFile = f

	// Create query logger
	var writer io.Writer = f
	if l.config.QueryLogFormat == "console" {
		writer = zerolog.ConsoleWriter{
			Out:        f,
			TimeFormat: time.RFC3339,
			NoColor:    true,
		}
	}

	l.queryLog = zerolog.New(writer).With().Timestamp().Logger()

	return nil
}

// System logger methods

// Debug logs a debug message
func (l *Logger) Debug() *zerolog.Event {
	return l.systemLog.Debug()
}

// Info logs an info message
func (l *Logger) Info() *zerolog.Event {
	return l.systemLog.Info()
}

// Warn logs a warning message
func (l *Logger) Warn() *zerolog.Event {
	return l.systemLog.Warn()
}

// Error logs an error message
func (l *Logger) Error() *zerolog.Event {
	return l.systemLog.Error()
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal() *zerolog.Event {
	return l.systemLog.Fatal()
}

// QueryLogEntry represents a DNS query log entry
type QueryLogEntry struct {
	Timestamp     time.Time `json:"timestamp"`
	ClientIP      string    `json:"client_ip"`
	ClientPort    int       `json:"client_port"`
	Protocol      string    `json:"protocol"`
	QName         string    `json:"qname"`
	QType         string    `json:"qtype"`
	QClass        string    `json:"qclass"`
	RCode         string    `json:"rcode"`
	AnswerCount   int       `json:"answer_count"`
	Latency       int64     `json:"latency_ms"`
	CacheHit      bool      `json:"cache_hit"`
	Blocked       bool      `json:"blocked"`
	BlockReason   string    `json:"block_reason,omitempty"`
	Upstream      string    `json:"upstream,omitempty"`
	DNSSEC        bool      `json:"dnssec"`
	ThreatScore   int32     `json:"threat_score,omitempty"`
	ThreatDetails string    `json:"threat_details,omitempty"`
}

// LogQuery logs a DNS query. Thread-safe: holds l.mu for the full body.
func (l *Logger) LogQuery(entry QueryLogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.config.EnableQueryLog {
		return
	}
	l.queriesLogged.Add(1)

	l.queryLog.Info().
		Time("timestamp", entry.Timestamp).
		Str("client_ip", entry.ClientIP).
		Int("client_port", entry.ClientPort).
		Str("protocol", entry.Protocol).
		Str("qname", entry.QName).
		Str("qtype", entry.QType).
		Str("qclass", entry.QClass).
		Str("rcode", entry.RCode).
		Int("answer_count", entry.AnswerCount).
		Int64("latency_ms", entry.Latency).
		Bool("cache_hit", entry.CacheHit).
		Bool("blocked", entry.Blocked).
		Str("block_reason", entry.BlockReason).
		Str("upstream", entry.Upstream).
		Bool("dnssec", entry.DNSSEC).
		Int32("threat_score", entry.ThreatScore).
		Str("threat_details", entry.ThreatDetails).
		Msg("DNS query")
}

// Close closes the logger and releases resources
func (l *Logger) Close() error {
	if l.queryFile != nil {
		return l.queryFile.Close()
	}
	return nil
}

// SetQueryLogEnabled dynamically enables or disables query logging.
// Thread-safe; holds l.mu during file open/close.
func (l *Logger) SetQueryLogEnabled(enabled bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if enabled && !l.config.EnableQueryLog {
		l.config.EnableQueryLog = true
		return l.setupQueryLog()
	}
	if !enabled && l.config.EnableQueryLog {
		l.config.EnableQueryLog = false
		if l.queryFile != nil {
			_ = l.queryFile.Close()
			l.queryFile = nil
		}
	}
	return nil
}

// IsQueryLogEnabled returns whether query logging is currently active.
func (l *Logger) IsQueryLogEnabled() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.config.EnableQueryLog
}

// QueryLogConfig returns the current query log path and format.
func (l *Logger) QueryLogConfig() (path, format string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.config.QueryLogPath, l.config.QueryLogFormat
}

// QueriesLogged returns the number of queries logged since startup.
func (l *Logger) QueriesLogged() int64 {
	return l.queriesLogged.Load()
}

// Global logger instance (will be initialized by main)
var globalLogger *Logger

// SetGlobalLogger sets the global logger instance
func SetGlobalLogger(l *Logger) {
	globalLogger = l
}

// GetGlobalLogger returns the global logger instance
func GetGlobalLogger() *Logger {
	return globalLogger
}

// Convenience functions for global logger

// Debug logs a debug message using the global logger
func Debug() *zerolog.Event {
	if globalLogger != nil {
		return globalLogger.Debug()
	}
	return log.Debug()
}

// Info logs an info message using the global logger
func Info() *zerolog.Event {
	if globalLogger != nil {
		return globalLogger.Info()
	}
	return log.Info()
}

// Warn logs a warning message using the global logger
func Warn() *zerolog.Event {
	if globalLogger != nil {
		return globalLogger.Warn()
	}
	return log.Warn()
}

// Error logs an error message using the global logger
func Error() *zerolog.Event {
	if globalLogger != nil {
		return globalLogger.Error()
	}
	return log.Error()
}

// Fatal logs a fatal message and exits using the global logger
func Fatal() *zerolog.Event {
	if globalLogger != nil {
		return globalLogger.Fatal()
	}
	return log.Fatal()
}

// LogQuery logs a query using the global logger
func LogQuery(entry QueryLogEntry) {
	if globalLogger != nil {
		globalLogger.LogQuery(entry)
	}
}
