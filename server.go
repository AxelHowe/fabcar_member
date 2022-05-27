package main

import (
	"bytes"
	"encoding/json"
	"fabcar_member/member"
	"fmt"

	// "fmt"
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
		// authorized.GET("/reports", getAllReports)
		authorized.POST("/reports", queryUserReport)
		authorized.POST("/createReports", createReport)
		authorized.POST("/reports/changeSigner", changeSigner)
		// authorized.POST("/reports/changeNote",changeNote)
		authorized.POST("/reports/changeSdate", changeSdate)
		authorized.POST("/reports/changeSbad", changeSbad)
		authorized.POST("/reports/changeOcargo", changeOcargo)
		authorized.POST("/reports/changeCcargo", changeCcargo)
		authorized.POST("/reports/changeInvoice", changeInvoice)
		authorized.POST("/reports/changeCbill", changeCbill)
		authorized.POST("/reports/Finish", Finish)

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
	if err != nil {
		log.Println(err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err.Error(),
		})
		return
	}
	err = member.Register(body.Username, body.Password, body.Role)
	if err != nil {
		log.Println(err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{
			"status": false,
			"error":  err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  true,
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
			"status": false,
			"error":  err.Error(),
		})
		return
	}

	// check account and password is correct
	err = member.Login(body.Username, body.Password)
	if err != nil {
		log.Println(err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{
			"status": false,
			"message": "Unauthorized",
			"error":  err.Error(),
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
			ExpiresAt: now.Add(10 * time.Minute).Unix(), // 10 分鐘後過期
			Id:        jwtId,
			IssuedAt:  now.Unix(),
			Issuer:    "ginJWT",
			// NotBefore: now.Add(10 * time.Second).Unix(),
			Subject:   body.Username,
		},
	}
	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := tokenClaims.SignedString(jwtSecret)
	if err != nil {
		log.Println(err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": false,
			"error":  err.Error(),
		})
		return
	}

	role := member.CheckUserRole(body.Username)
	c.JSON(http.StatusOK, gin.H{
		"status": true,
		"token":  token,
		"role":   role,
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
	// fmt.Println("Authorization:" + auth)
	var authSplit []string = strings.Split(auth, "Bearer ")
	if len(authSplit) != 2 {
		log.Println("message: can not handle this token")
		c.JSON(http.StatusUnauthorized, gin.H{
			"status":  false,
			"message": "can not handle this token",
		})
		c.Abort()
		return
	}
	var token string = authSplit[1]
	fmt.Println("token:" + token)
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
		log.Println("error: " + message)
		c.JSON(http.StatusUnauthorized, gin.H{
			"status": false,
			"error":  message,
		})
		c.Abort()
		return
	}

	if claims, ok := tokenClaims.Claims.(*Claims); ok && tokenClaims.Valid {
		// fmt.Println("username:", claims.Username)
		// fmt.Println("password:", claims.Password)
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
	Process      string `json:"process"`      //流程狀態
	Urgent       string `json:"urgent"`       //交貨急迫性
	Odate        string `json:"odate"`        // 訂單日期
	Ddate        string `json:"ddate"`        //預交日期
	Purchase     string `json:"purchase"`     //採購人員
	Sname        string `json:"sname"`        //供應商代號
	Supplier     string `json:"supplier"`     //供應商名稱
	Signer       string `json:"signer"`       //供應商簽署人員
	Invoice      string `json:"invoice"`      //發票號碼
	Pname        string `json:"pname"`        //採購品名
	Pquantity    string `json:"pquantity"`    //採購數量
	Price        string `json:"price"`        //採購單價
	Sdate        string `json:"sdate"`        //交貨日期
	Amount       string `json:"amount"`       //交貨數量
	Bad          string `json:"bad"`          //不良品數量
	Bnote        string `json:"bnote"`        //不良品備註
	Sbad         string `json:"sbad"`         //不良品總量
	Volume       string `json:"volume"`       //已交貨總量
	Ntraded      string `json:"ntraded"`      //未交貨總量
	Oestablished string `json:"oestablished"` //訂單接受
	Ocargo       string `json:"ocargo"`       //交貨完成
	Ccargo       string `json:"ccargo"`       //確認交貨完成
	Bill         string `json:"bill"`         //發票開立
	Cbill        string `json:"cbill"`        //確認發票開立
	Finish       string `json:"finish"`       //訂單完成
	Note         string `json:"note"`         //備註
	Historys     []HistoryItem
}

type HistoryItem struct {
	TxId   string
	Report Report
}
type Receive struct {
	Status bool   `json:"status"`
	Key    string `json:"key"`
	Report Report `json:"report"`
	// Reports Report `json:"reports"`
	Message string        `json:"message"`
	Error   receive_error `json:"error"`
}

type receive_error struct {
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

	// fmt.Println("====")
	// fmt.Println(r.Report)
	// fmt.Println("====")
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
	// fmt.Println("====GET===")
	// fmt.Println(string(bodyBytes))
	// fmt.Println("====")

	json.Unmarshal(bodyBytes, &rep)
	// fmt.Println("====rep")
	// fmt.Println(rep)
	// fmt.Println(r.Status)
	return rep, nil
}

func POST(path string, report Report) (Receive, error) {
	domain := "http://localhost:9901/"
	url := domain + path
	// fmt.Println(report) // 參數
	j, _ := json.Marshal(report)
	jsonBytes := bytes.NewBuffer(j)
	// fmt.Println(jsonBytes) // 參數
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

	json.Unmarshal(bodyBytes, &rep)
	// fmt.Println("====bodyBytes")
	// fmt.Println(string(bodyBytes))
	// fmt.Println("====rep")
	// fmt.Println(rep)
	return rep, nil
}

func createReport(c *gin.Context) {

	var req Request
	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err.Error(),
		})
		return
	}
	if member.CheckUserRole(req.Username) != permission.createReport {
		log.Println("no permission")
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": "no permission",
		})
		return
	}

	r, err := POST("reports", req.Report)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": err,
		})
		return
	}

	if !r.Status {
		log.Println(r.Error)
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": r.Error,
		})
		return
	}

	// TODO: 產生訂單要移到上面判斷，還要多加判斷此訂單編號是否已存在
	err = member.Generate_report(req.Username, req.Report.Key)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  r.Status,
		"message": "create report success.",
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
			"status": false,
			"error":  err.Error(),
		})
		return
	}

	report_keys := member.Query_user_report(req.Username)
	reports := make([]Report, 0)
	for _, i := range report_keys {
		// fmt.Println("key:" + i)
		r, err := GET("reports/" + i)
		if err != nil {
			log.Println(err.Error())
			c.JSON(http.StatusBadRequest, gin.H{
				"status":  false,
				"message": err.Error(),
			})
			return
		}
		r.Report.Key = i
		reports = append(reports, r.Report)
	}

	// 本來是用 for 迴圈 針對一筆筆訂單編號去請求資料
	// 看要不要改成直接用 queryAllReports 去處理
	// r, err := GET("reports/")
	// if err != nil {
	// 	log.Println(err.Error())
	// 	c.JSON(http.StatusBadRequest, gin.H{
	// 		"status":  false,
	// 		"message": err.Error(),
	// 	})
	// 	return
	// }

	c.JSON(http.StatusOK, gin.H{
		"status": true,
		"report": reports,
	})
	return
}

func changeSigner(c *gin.Context) {

	var req Request
	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err.Error(),
		})
		return
	}

	if member.CheckUserRole(req.Username) != permission.changeSigner {
		log.Println("no permission")
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"msg":    "no permission",
		})
		return
	}

	r, err := POST("reports/changeSigner", req.Report)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err,
		})
		return
	}
	if !r.Status {
		log.Println(r.Error)
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": r.Error,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": r.Message,
	})
	return
}

func changeSbad(c *gin.Context) {

	var req Request
	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err.Error(),
		})
		return
	}

	if member.CheckUserRole(req.Username) != permission.changeSbad {
		log.Println("no permission")
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"msg":    "no permission",
		})
		return
	}

	r, err := POST("reports/changeSbad", req.Report)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err,
		})
		return
	}
	if !r.Status {
		log.Println(r.Error)
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": r.Error,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": r.Message,
	})
	return
}

func changeSdate(c *gin.Context) {

	var req Request
	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err.Error(),
		})
		return
	}

	if member.CheckUserRole(req.Username) != permission.changeSdate {
		log.Println("no permission")
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"msg":    "no permission",
		})
		return
	}

	r, err := POST("reports/changeSdate", req.Report)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err,
		})
		return
	}
	if !r.Status {
		log.Println(r.Error)
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": r.Error,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": r.Message,
	})
	return
}

func changeOcargo(c *gin.Context) {

	var req Request
	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err.Error(),
		})
		return
	}

	if member.CheckUserRole(req.Username) != permission.changeOcargo {
		log.Println("no permission")
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"msg":    "no permission",
		})
		return
	}

	r, err := POST("reports/changeOcargo", req.Report)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err,
		})
		return
	}
	if !r.Status {
		log.Println(r.Error)
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": r.Error,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": r.Message,
	})
	return
}

func changeCcargo(c *gin.Context) {

	var req Request
	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err.Error(),
		})
		return
	}

	if member.CheckUserRole(req.Username) != permission.changeCcargo {
		log.Println("no permission")
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"msg":    "no permission",
		})
		return
	}

	r, err := POST("reports/changeCcargo", req.Report)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err,
		})
		return
	}
	if !r.Status {
		log.Println(r.Error)
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": r.Error,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": r.Message,
	})
	return
}

func changeInvoice(c *gin.Context) {

	var req Request
	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err.Error(),
		})
		return
	}

	if member.CheckUserRole(req.Username) != permission.changeInvoice {
		log.Println("no permission")
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"msg":    "no permission",
		})
		return
	}

	r, err := POST("reports/changeInvoice", req.Report)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err,
		})
		return
	}
	if !r.Status {
		log.Println(r.Error)
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": r.Error,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": r.Message,
	})
	return
}

func changeCbill(c *gin.Context) {

	var req Request
	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err.Error(),
		})
		return
	}

	if member.CheckUserRole(req.Username) != permission.changeCbill {
		log.Println("no permission")
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"msg":    "no permission",
		})
		return
	}

	r, err := POST("reports/changeCbill", req.Report)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err,
		})
		return
	}
	if !r.Status {
		log.Println(r.Error)
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": r.Error,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": r.Message,
	})
	return
}
func Finish(c *gin.Context) {

	var req Request
	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err.Error(),
		})
		return
	}

	if member.CheckUserRole(req.Username) != permission.Finish {
		log.Println("no permission")
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"msg":    "no permission",
		})
		return
	}

	r, err := POST("reports/Finish", req.Report)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": false,
			"error":  err,
		})
		return
	}
	if !r.Status {
		log.Println(r.Error)
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": r.Error,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": r.Message,
	})
	return
}

// {
//關於訂單流程的TODO
// TODO: 確認這個USER是此訂單的人 (這好像應該寫在fabcar.go)
// TODO 搜尋訂單的process 確認流程狀態 (這好像應該寫在fabcar.go)

// TODO: 列出所有需要的欄位
// TODO:好像也可以給app.js判斷
// if req.Report.Urgent == "" || req.Report.Odate == "" {
// 	c.JSON(http.StatusBadRequest, gin.H{
// 		"msg": "missing body.",
// 	})
// 	return
// }
// }

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

type Request struct {
	Username string `json:"username"`
	Report   Report `json:"report"`
}
