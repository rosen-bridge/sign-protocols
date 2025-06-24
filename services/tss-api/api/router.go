package api

import (
	"github.com/brpaz/echozap"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"rosen-bridge/tss-api/logger"
)

// InitRouting Initialize Router
func InitRouting(e *echo.Echo, tssController TssController) {
	// Middleware
	zapLogger := logger.NewLogger().Named("tss/http")

	e.Validator = tssController
	e.Use(echozap.ZapLogger(zapLogger))
	e.Use(middleware.Recover())

	e.GET("/threshold", tssController.Threshold())
	e.POST("/getPK", tssController.GetPublicKey())
	e.POST("/sign", tssController.Sign())
	e.POST("/keygen", tssController.Keygen())
	e.POST("/message", tssController.Message())
}
