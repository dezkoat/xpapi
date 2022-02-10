package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/dezkoat/xcntn/proto"
)

var (
	serverAddr = flag.String("addr", "localhost:50001", "Server address")
)

func grpcInit() {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))

	conn, err := grpc.Dial(*serverAddr, opts...)
	if err != nil {
		log.Fatalf("Fail to dial: %v", err)
	} else {
		log.Printf("Success dialing %v", *serverAddr)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := pb.NewContentClient(conn)
	post, err := client.GetPost(ctx, &pb.GetPostRequest{Id: "1234"})
	if err != nil {
		log.Fatalf("Error calling GetPost: %v", err)
	} else {
		log.Printf("%v: %v", post.Title, post.Text)
	}

}

func restInit() {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	r.Run() // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}

func main() {
	grpcInit()
	restInit()
}
