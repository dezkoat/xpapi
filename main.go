package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	xcntn "github.com/dezkoat/xcntn/proto"
	xuser "github.com/dezkoat/xuser/proto"
)

var (
	xcntnAddr     = flag.String("cntn-addr", "localhost:50001", "Content Server address")
	xuserAddr     = flag.String("user-addr", "localhost:50002", "User Server address")
	publicKeyPath = flag.String("key", "./key/public.pem", "Public Key File Path used in User Credentials Authentication")
)

type PublicAPIService struct {
	ContentConnection *grpc.ClientConn
	Content           xcntn.ContentClient
	UserConnection    *grpc.ClientConn
	User              xuser.UserClient
	UserPublicKey     *rsa.PublicKey
}

type LoginInfo struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type UserClaims struct {
	*jwt.StandardClaims
	Email string
}

func GRPCInit() *PublicAPIService {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))

	xcntnConn, err := grpc.Dial(*xcntnAddr, opts...)
	if err != nil {
		log.Fatalf("Fail to dial: %v", err)
	}

	xuserConn, err := grpc.Dial(*xuserAddr, opts...)
	if err != nil {
		log.Fatalf("Fail to dial: %v", err)
	}

	return &PublicAPIService{
		ContentConnection: xcntnConn,
		Content:           xcntn.NewContentClient(xcntnConn),
		UserConnection:    xuserConn,
		User:              xuser.NewUserClient(xuserConn),
	}
}

func (s *PublicAPIService) ReadAndStorePublicKey() {
	pub, err := ioutil.ReadFile(*publicKeyPath)
	if err != nil {
		log.Fatalf("Error reading file %v: %v", publicKeyPath, err)
	}

	pubPem, _ := pem.Decode(pub)
	pubKey, err := x509.ParsePKIXPublicKey(pubPem.Bytes)
	if err != nil {
		log.Fatalf("Error reading public key %v", err)
	}

	s.UserPublicKey = pubKey.(*rsa.PublicKey)
}

func (s *PublicAPIService) AuthUser(c *gin.Context) {
	if s.UserPublicKey == nil {
		s.ReadAndStorePublicKey()
	}

	bearerToken := c.Request.Header["Authorization"]
	if len(bearerToken) == 0 {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"message": "Authorization required",
		})
		return
	}
	if len(bearerToken) != 1 {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "Unexpected error",
		})
		return
	}

	bearerTokens := strings.Split(bearerToken[0], " ")
	if len(bearerTokens) != 2 {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "Unexpected error",
		})
		return
	}

	_, err := jwt.ParseWithClaims(bearerTokens[1], &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return s.UserPublicKey, nil
	})

	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"message": "Invalid Credentials. Error: " + err.Error(),
		})
		return
	}
}

func (s *PublicAPIService) Login(c *gin.Context) {
	var login LoginInfo
	c.BindJSON(&login)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	userToken, err := s.User.Login(
		ctx,
		&xuser.UserInfo{
			Username: login.Username,
			Password: login.Password,
		},
	)
	if err != nil {
		log.Printf("Error calling Login: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Unexpected Error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": userToken.Token,
	})
}

func (s *PublicAPIService) PingAdmin(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	post, err := s.Content.GetPost(ctx, &xcntn.GetPostRequest{Id: "1234"})
	if err != nil {
		log.Printf("Error calling GetPost: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Unexpected Error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Admin says: " + post.Title,
	})
}

func (s *PublicAPIService) Ping(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	post, err := s.Content.GetPost(ctx, &xcntn.GetPostRequest{Id: "1234"})
	if err != nil {
		log.Printf("Error calling GetPost: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Unexpected Error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": post.Title,
	})
}

func RestInit(papiService *PublicAPIService) {
	r := gin.Default()
	r.SetTrustedProxies(nil)

	admin := r.Group("/admin", papiService.AuthUser)
	{
		admin.GET("/ping", papiService.PingAdmin)
	}

	r.POST("/login", papiService.Login)

	r.GET("/ping", papiService.Ping)

	r.Run()
}

func main() {
	papiService := GRPCInit()
	defer papiService.ContentConnection.Close()
	defer papiService.UserConnection.Close()

	RestInit(papiService)
}
