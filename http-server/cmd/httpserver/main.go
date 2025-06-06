package main

import (
	"go-cpp-grpc-service/http-server/internal/httpserver"
	"log"

	"github.com/joho/godotenv"
)

func main() {

	if err := godotenv.Load("./server.env"); err != nil {
		log.Fatal("Error loading .env file")
	}

	cfg := httpserver.MustLoadConfig();

	server := httpserver.New(cfg)
	if err := server.Start(); err != nil {
		log.Fatalf("Error starting http server: %s", err)
	}


}