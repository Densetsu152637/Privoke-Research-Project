package main

import (
	"log"
	"net"
	"os"
	"strconv"

	pb "github.com/privoke/research-project/services/model-streaming-service/gen/privoke/v1"
	"google.golang.org/grpc"
)

const (
	serviceName             = "model-streaming-service"
	maxRequestMessageBytes  = 64 * 1024
	maxResponseMessageBytes = 8 * 1024 * 1024
	maxConcurrentStreams    = 32
)

func main() {
	config, err := loadServerConfig()
	if err != nil {
		log.Fatal(err)
	}
	if isHealthcheck(os.Args) {
		if err := grpcHealthcheck(config.port); err != nil {
			log.Printf("healthcheck failed: %v", err)
			os.Exit(1)
		}
		return
	}
	catalog, err := loadModelCatalog(config.artifactDir, config.latestModelID)
	if err != nil {
		log.Fatalf("load model catalog: %v", err)
	}
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(config.port))
	if err != nil {
		log.Fatalf("listen failed: %v", err)
	}

	server := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxRequestMessageBytes),
		grpc.MaxSendMsgSize(maxResponseMessageBytes),
		grpc.MaxConcurrentStreams(maxConcurrentStreams),
	)
	pb.RegisterModelStreamingServiceServer(server, &streamingServer{
		catalog: catalog,
	})
	log.Printf(
		"%s listening on %d latest=%q models=%v",
		serviceName,
		config.port,
		catalog.latestModelID,
		catalog.modelIDs(),
	)
	if err := server.Serve(listener); err != nil {
		log.Fatalf("serve failed: %v", err)
	}
}

func isHealthcheck(args []string) bool {
	return len(args) > 1 && args[1] == "healthcheck"
}
