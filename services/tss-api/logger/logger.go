package logger

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
	"rosen-bridge/tss-api/models"
)

const (
	// DPanic, Panic and Fatal level can not be set by user
	DebugLevelStr   string = "debug"
	InfoLevelStr    string = "info"
	WarningLevelStr string = "warning"
	ErrorLevelStr   string = "error"
)

var (
	globalLogger *zap.Logger
)

// call it in defer
func Sync() error {
	return globalLogger.Sync()
}

func Init(logFile string, config models.Config, dev bool) error {

	var level zapcore.Level
	switch config.LogLevel {
	case DebugLevelStr:
		level = zap.DebugLevel
	case InfoLevelStr:
		level = zap.InfoLevel
	case WarningLevelStr:
		level = zap.WarnLevel
	case ErrorLevelStr:
		level = zap.ErrorLevel
	default:
		return fmt.Errorf("unknown log level %s", config.LogLevel)
	}

	ws := zapcore.AddSync(
		&lumberjack.Logger{
			Filename:   logFile,
			MaxSize:    config.LogMaxSize, //MB
			MaxBackups: config.LogMaxBackups,
			MaxAge:     config.LogMaxAge, //days
			Compress:   false,
		},
	)

	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	core := zapcore.NewCore(
		// use NewConsoleEncoder for human-readable output
		zapcore.NewConsoleEncoder(encoderConfig),
		// write to stdout as well as log files
		zapcore.NewMultiWriteSyncer(zapcore.AddSync(os.Stdout), ws),

		zap.NewAtomicLevelAt(level),
	)
	var _globalLogger *zap.Logger
	if dev {
		_globalLogger = zap.New(core, zap.AddCaller(), zap.Development())
	} else {
		_globalLogger = zap.New(core, zap.AddCaller(), zap.AddStacktrace(zap.ErrorLevel))
	}
	zap.ReplaceGlobals(_globalLogger)
	globalLogger = _globalLogger
	return nil
}

func NewSugar(name string) *zap.SugaredLogger {
	return globalLogger.Named("tss/" + name).Sugar()
}

func NewLogger() *zap.Logger {
	return globalLogger
}
