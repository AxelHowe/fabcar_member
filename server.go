package main

import (
	"bytes"
	"encoding/json"
	"fabcar_member/member"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
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
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"http://localhost:8080"}
	corsConfig.AllowMethods = []string{"GET", "POST", "PUT"}
	corsConfig.AllowHeaders = []string{"Authorization", "Origin", "content-type"}
	corsConfig.AllowCredentials = true
	corsConfig.ExposeHeaders = []string{"Content-Length"}
	corsConfig.MaxAge = 12 * time.Hour
	router.Use(cors.New(corsConfig))
	router.Use(CORSMiddleware)

	router.POST("/register", register)
	router.POST("/login", login)
	router.POST("/auth", AuthRequired)
	authorized := router.Group("/")
	authorized.Use(AuthRequired)
	{
		authorized.GET("/reports", getAllReports)
		authorized.POST("/reports", createReport)
		authorized.POST("/reports/changeSigner", changeSigner)
		authorized.POST("/reports/changeNote")
		authorized.POST("/reports/changeSdate")
		authorized.POST("/reports/changeSbad", changeSbad)
		authorized.POST("/reports/changeOcargo")
		authorized.POST("/reports/changeCcargo")
		authorized.POST("/reports/changeInvoice")
		authorized.POST("/reports/changeCbill")
		authorized.POST("/reports/Finish")

	}
	router.Run(":8888")
}

func CORSMiddleware(c *gin.Context) {

	c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")

	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(204)
		return
	}

	c.Next()

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
	//     "message": "Unauthorized",
	// })
}

// validate JWT
func AuthRequired(c *gin.Context) {
	c.Next() // test 用
	return
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

type Report struct {
	Key          string `json:"key"`
	Process      string `json:"process"`
	Urgent       string `json:"urgent"`
	Odate        string `json:"odate"`
	Ddate        string `json:"ddate"`
	Purchase     string `json:"purchase"`
	Sname        string `json:"sname"`
	Supplier     string `json:"supplier"`
	Signer       string `json:"signer"`
	Invoice      string `json:"invoice"`
	Pname        string `json:"pname"`
	Pquantity    string `json:"pquantity"`
	Price        string `json:"price"`
	Sdate        string `json:"sdate"`
	Amount       string `json:"amount"`
	Sbad         string `json:"sbad"`
	Volume       string `json:"volume"`
	Ntraded      string `json:"ntraded"`
	Oestablished string `json:"oestablished"`
	Ocargo       string `json:"ocargo"`
	Ccargo       string `json:"ccargo"`
	Bill         string `json:"bill"`
	Cbill        string `json:"cbill"`
	Finish       string `json:"finish"`
	Note         string `json:"note"`
	Historys     []HistoryItem
}

type HistoryItem struct {
	TxId   string
	Report Report
}
type Receive struct {
	Status bool `json:"status"`
	Report Report `json:"report",json:"reports"`
	Message string `json:"message"`
}

func getAllReports(c *gin.Context) {

	r, err := GET("reports/")
	if err != nil {
		// TODO: http 回傳500
		log.Println(err.Error())
		// TODO c.json statuserror
		// c.JSON(http.StatusBadRequest, r.Report)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": "false",
			"error":  err.Error(),
		})
		return
	}
	// var rep = Receive{Status: "200 OK"}
	// fmt.Println(rep)

	fmt.Println("====")
	fmt.Println(r.Report)
	fmt.Println("====")
	c.JSON(http.StatusOK, gin.H{
		"status": r.Status,
		"report": r.Report,
		// "msg": "you are doing get_reports",
	})
	return
}

//TODO return (res,err)
func GET(path string) (Receive, error) {
	domain := "http://localhost:9901/"
	url := domain + path
	r, err := http.Get(url)
	var rep Receive
	if err != nil {
		// log.Fatal(err)
		log.Println(err.Error())
		return rep, err
	}
	defer r.Body.Close()
	// return *r
	// _, err :=io.ReadAll(r.Body)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		// log.Fatal(err)
		log.Println(err.Error())
		return rep, err
	}
	// fmt.Println(r)
	fmt.Println("====GET===")
	fmt.Println(string(bodyBytes))
	fmt.Println("====")

	json.Unmarshal(bodyBytes, &rep)
	fmt.Println("====rep")
	fmt.Println(rep)
	// fmt.Println(r.Status)
	return rep, nil
}

func POST(path string, report Report) (Receive, error) {
	domain := "http://localhost:9901/"
	url := domain + path

	j, _ := json.Marshal(report)
	jsonBytes := bytes.NewBuffer(j)
	var rep Receive
	r, err := http.Post(url, "application/json", jsonBytes)
	if err != nil {
		// log.Fatal(err)
		log.Println(err.Error())
		return rep, err
	}
	defer r.Body.Close()

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		// log.Fatal(err)
		log.Println(err.Error())
		return rep, err
	}
	fmt.Println("====bodyBytes")
	fmt.Println(string(bodyBytes))
	fmt.Println("====rep")
	fmt.Println(rep)
	json.Unmarshal(bodyBytes, &rep)
	return rep, nil
}

func createReport(c *gin.Context) {
	fmt.Println("===start===")

	var req struct {
		Username string `json:"username"`
		Report   Report `json:"report"`
		// Password string
	}
	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	fmt.Println("===")
	fmt.Println(req.Report)

	if member.CheckUserRole(req.Username) != "order" {
		fmt.Println("check===")
		fmt.Println(req.Username)
		fmt.Println(member.CheckUserRole(req.Username))
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "no permission",
		})
		return
	}
	//TODO: 列出所有需要的欄位
	// TODO:好像也可以給app.js判斷
	if req.Report.Urgent == "" || req.Report.Odate == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "missing body.",
		})
		return
	}

	// params := Report{Process:}
	r, err := POST("reports", req.Report)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}
	// TODO: 產生訂單要移到上面判斷，還要多加判斷此訂單編號是否已存在
	err = member.Generate_report(req.Username, req.Report.Key)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status": r.Status,
		"msg":    "create report success.",
	})
	return
}

func queryUserReport(c *gin.Context) {

	var req struct {
		Username string `json:"username"`
		Report   Report `json:"report"`
		// Password string
	}
	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	report_keys := member.Query_user_report(req.Username)

	for _, i := range report_keys {
		r, err := GET("reports/" + i)
		if err != nil {
			log.Println(err.Error())
			// TODO c.json statuserror
		}
		fmt.Println(r)
	}
	// TODO:還沒處理好
	// var rep = Receive{Status: "200 OK"}
	// fmt.Println(rep)
	c.JSON(http.StatusOK, gin.H{
		"status": "123",
		// "msg": "you are doing get_reports",
	})
	return
}

func changeSigner(c *gin.Context) {

	var req struct {
		Username string `json:"username"`
		Report   Report `json:"report"`
		// Password string
	}
	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	// TODO: 確認這個USER是此訂單的人
	if member.CheckUserRole(req.Username) != permission.changeSigner {
		// fmt.Println("check===")
		// fmt.Println(req.Username)
		// fmt.Println(member.CheckUserRole(req.Username))
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "no permission",
		})
		return
	}
	//TODO 搜尋訂單的process 確認流程狀態 (這好像應該寫在fabcar.go)


	//TODO: 列出所有需要的欄位
	// TODO:好像也可以給app.js判斷
	if req.Report.Urgent == "" || req.Report.Odate == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "missing body.",
		})
		return
	}

	// params := Report{Process:}
	r, err := POST("reports/changeSigner", req.Report)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}
	fmt.Println(r)
}

func changeSbad(c *gin.Context) {

	var req struct {
		Username string `json:"username"`
		Report   Report `json:"report"`
		// Password string
	}
	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	// TODO: 確認這個USER是此訂單的人
	if member.CheckUserRole(req.Username) != permission.changeSbad {
		fmt.Println("checkUserRole===")
		fmt.Println(req.Username)
		fmt.Println(member.CheckUserRole(req.Username))
		fmt.Println(permission.changeSbad)
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "no permission",
		})
		return
	}
	//TODO 搜尋訂單的process 確認流程狀態 (這好像應該寫在fabcar.go)


	//TODO: 列出所有需要的欄位
	// TODO:好像也可以給app.js判斷
	if req.Report.Urgent == "" || req.Report.Odate == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "missing body.",
		})
		return
	}

	// params := Report{Process:}
	r, err := POST("reports/changeSbad", req.Report)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}
	fmt.Println(r)

	c.JSON(http.StatusOK, gin.H{
		"status": r.Status,
		"message": r.Message,
		// "msg": "you are doing get_reports",
	})
	return
}

type Permission struct {
	createReport  string
	changeSigner  string
	changeSdate   string
	changeSbad    string
	changeOcargo  string
	changeCcargo  string
	changeInvoice string
	changeCbill   string
	Finish        string
}

var permission = Permission{
	createReport:  "order",
	changeSigner:  "supplier",
	changeSdate:   "supplier",
	changeSbad:    "order",
	changeOcargo:  "supplier",
	changeCcargo:  "order",
	changeInvoice: "supplier",
	changeCbill:   "order",
	Finish:        "order",
}
