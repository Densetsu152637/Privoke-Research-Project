package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	pb "github.com/privoke/research-project/services/model-streaming-service/gen/privoke/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func grpcHealthcheck(port int) error {
	connection, err := grpc.NewClient(
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return err
	}
	defer connection.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := pb.NewModelStreamingServiceClient(connection).Health(
		ctx,
		&pb.HealthRequest{},
	)
	if err != nil {
		return err
	}
	if response.GetService() != serviceName || response.GetStatus() != "SERVING" {
		return fmt.Errorf(
			"unexpected health response service=%q status=%q",
			response.GetService(),
			response.GetStatus(),
		)
	}
	return nil
}
