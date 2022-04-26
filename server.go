package main

import (
	"fabcar_member/member"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// custom claims
type Claims struct {
	Username string `json:"account"`
	Password string `json:"password"`
	jwt.StandardClaims
}

// jwt secret key
var jwtSecret = []byte(os.Getenv("SECRET_KEY"))

func main() {

	// fmt.Println(member.Generate_report("1", "2"))
	router := gin.Default()

	router.POST("/register", register)
	router.POST("/login", login)
	router.POST("/auth", AuthRequired)
	authorized := router.Group("/")
	authorized.Use(AuthRequired)
	{
		authorized.GET("/reports",getReports)
		authorized.POST("/reports")
		authorized.POST("/reports/changSigner")
		authorized.POST("/reports/changeNote")
		authorized.POST("/reports/changSdate")
		authorized.POST("/reports/changSbad")
		authorized.POST("/reports/changOcargo")
		authorized.POST("/reports/changCcargo")
		authorized.POST("/reports/changInvoice")
		authorized.POST("/reports/changCbill")
		authorized.POST("/reports/Finish")

	}
	router.Run(":8080")
}

func register(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	err := c.ShouldBindJSON(&body)
	fmt.Println("===")
	fmt.Println(body.Username)
	fmt.Println(body.Password)
	fmt.Println(body.Role)
	fmt.Println("===")
	if err != nil {
		log.Println(err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	err = member.Register(body.Username, body.Password, body.Role)
	if err != nil {
		log.Println(err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "register success",
	})
	return

}

func login(c *gin.Context) {
	// validate request body
	var body struct {
		Username string
		Password string
	}
	err := c.ShouldBindJSON(&body)
	if err != nil {
		log.Println(err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// check account and password is correct
	err = member.Login(body.Username, body.Password)
	if err != nil {
		log.Println(err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}

	now := time.Now()
	jwtId := body.Username + strconv.FormatInt(now.Unix(), 10)
	// role := "Member"

	// set claims and sign
	claims := Claims{
		Username: body.Username,
		Password: body.Password,
		// Role:    role,
		StandardClaims: jwt.StandardClaims{
			Audience:  body.Username,
			ExpiresAt: now.Add(20 * time.Second).Unix(),
			Id:        jwtId,
			IssuedAt:  now.Unix(),
			Issuer:    "ginJWT",
			NotBefore: now.Add(10 * time.Second).Unix(),
			Subject:   body.Username,
		},
	}
	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := tokenClaims.SignedString(jwtSecret)
	if err != nil {
		log.Println(err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
	})
	return

	// incorrect account or password
	// c.JSON(http.StatusUnauthorized, gin.H{
	// 	"message": "Unauthorized",
	// })
}

// validate JWT
func AuthRequired(c *gin.Context) {
	auth := c.GetHeader("Authorization")
	token := strings.Split(auth, "Bearer ")[1]

	// parse and validate token for six things:
	// validationErrorMalformed => token is malformed
	// validationErrorUnverifiable => token could not be verified because of signing problems
	// validationErrorSignatureInvalid => signature validation failed
	// validationErrorExpired => exp validation failed
	// validationErrorNotValidYet => nbf validation failed
	// validationErrorIssuedAt => iat validation failed
	tokenClaims, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (i interface{}, err error) {
		//可以加入一些條件判斷，例如判斷讀取secret key環境變數是否成功，成功則回傳正確的key，不成功則回傳你自定義的error
		return jwtSecret, nil
	})

	if err != nil {
		var message string
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				message = "token is malformed"
			} else if ve.Errors&jwt.ValidationErrorUnverifiable != 0 {
				message = "token could not be verified because of signing problems"
			} else if ve.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
				message = "signature validation failed"
			} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
				message = "token is expired"
			} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
				message = "token is not yet valid before sometime"
			} else {
				message = "can not handle this token"
			}
		}
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": message,
		})
		c.Abort()
		return
	}

	if claims, ok := tokenClaims.Claims.(*Claims); ok && tokenClaims.Valid {
		fmt.Println("username:", claims.Username)
		fmt.Println("password:", claims.Password)
		c.Set("username", claims.Username)
		c.Set("password", claims.Password)
		c.Next()
	} else {
		c.Abort()
		return
	}
}

func getReports(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"msg": "you are doing get_reports",
	})
	return
}