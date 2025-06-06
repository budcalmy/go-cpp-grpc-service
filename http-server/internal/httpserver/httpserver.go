package httpserver

import (
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

type HTTPServer struct {
	config     *Config
	logger     *slog.Logger
	router     *mux.Router
}

func New(config *Config) *HTTPServer {
	server := &HTTPServer{
		config: config,
		router: mux.NewRouter(),
	}

	if err := server.configureLogger(); err != nil {
		log.Fatalf("Failed to configure logger: %s", err)
	}


	return server
}

func (s *HTTPServer) Start() error {
	s.configureRouter()

	s.logger.Info("Starting https server on address", "address", s.config.Server.Address)

	server := &http.Server{
		Addr:         s.config.Server.Address,
		Handler:      s.router,
		ReadTimeout:  s.config.Server.Timeout,
		WriteTimeout: s.config.Server.Timeout,
		IdleTimeout:  s.config.Server.IdleTimeout,
	}

	if err := server.ListenAndServe(); err != nil {
		s.logger.Error("Error starting server", "error", err, "address", s.config.Server.Address)
		return err
	}

	return nil
}

func (s *HTTPServer) configureLogger() error {
	var level slog.Level

	switch s.config.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	s.logger = slog.New(slog.NewTextHandler(os.Stderr, opts))

	return nil
}

func (s *HTTPServer) configureRouter() {
	// s.router.HandleFunc("/api/v1/init", initHandler.Handle()).Methods("POST")
	s.router.HandleFunc("/hello", s.handleHello())
}

func (s *HTTPServer) handleHello() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from router")
	}
}
