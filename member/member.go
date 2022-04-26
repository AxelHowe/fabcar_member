package member

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/crypto/scrypt"

	// "log"
	// "time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/joho/godotenv/autoload"
)

const (
	// SecretKEY              string = "JWT-Secret-Key"
	// DEFAULT_EXPIRE_SECONDS int    = 180 // default expired 1 minute
	PasswordHashBytes = 16
)

var db *sql.DB

func init() {
	// fmt.Println("Hello world")
	// SQL_USERNAME := os.Getenv("SQL_USERNAME")
	// SQL_PASSWORD := os.Getenv("SQL_PASSWORD")
	// SQL_SERVER_IP := os.Getenv("SQL_SERVER_IP")
	// SQL_SERVER_PORT := os.Getenv("SQL_SERVER_PORT")
	// const SQL_DATABASE = os.Getenv("SQL_DATABASE")

	var (
		USERNAME = os.Getenv("SQL_USERNAME")
		PASSWORD = os.Getenv("SQL_PASSWORD")
		NETWORK  = "tcp"
		SERVER   = os.Getenv("SQL_SERVER_IP")
		PORT, _  = strconv.Atoi(os.Getenv("SQL_SERVER_PORT"))
		DATABASE = os.Getenv("SQL_DATABASE")
	)
	// fmt.Println(Type(PORT))
	conn := fmt.Sprintf("%s:%s@%s(%s:%d)/%s?charset=utf8", USERNAME, PASSWORD, NETWORK, SERVER, PORT, DATABASE)
	var err error
	db, err = sql.Open("mysql", conn)
	if err != nil {
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		panic(err)
	}
	fmt.Println("DB OK")
	// 上面是登入SQL


	// result := Login("root", "root")
	// fmt.Println(result)

	// Query_user_report("root")

	// fmt.Println("======")

	// // Register("admin", "admin", "admin")
	// fmt.Println("======")
	// result = Login("admin", "admin")
	// fmt.Println(result)

	// defer db.Close()
}

// TODO: return error
func Login(username, password string) error {

	if len(username) == 0 || len(password) == 0 {
		fmt.Println("error: username or password is empty")
		// return false
		return errors.New("error: username or password is empty")
	}

	sql := `select * from user where username = ?`
	rows, err := db.Query(sql, username)

	if err != nil {
		fmt.Println("error: username doesn't exist")
		// return false
		return errors.New("error: username doesn't exist")
	}

	// 讀取SQL資料
	var user User
	// 不知道為啥要用 for 包住才可以用
	for rows.Next() {
		err = rows.Scan(&user.username, &user.password, &user.salt, &user.role)
	}

	if err != nil {
		fmt.Println("error: 123")
		// fmt.Println(err)
		// return false
		return errors.New("error: 123")
	}
	// 密碼做hash
	hash, err := GeneratePassHash(password, user.salt)
	if hash != user.password {
		fmt.Println("error: password error")
		// fmt.Println(hash)
		// fmt.Println(user.password)
		// return false
		fmt.Println(err)
		return errors.New("error: password error")
	}

	defer rows.Close()
	fmt.Println("登入成功")
	return nil
}

type User struct {
	username string
	password string
	salt     string
	role     string
}

type Report struct {
	report_key string
	username   string
}

// generate salt
func GenerateSalt() (salt string, err error) {

	buf := make([]byte, PasswordHashBytes)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {

		return "", errors.New("error: failed to generate user's salt")
	}

	return fmt.Sprintf("%x", buf), nil
}

// generate password hash
func GeneratePassHash(password string, salt string) (hash string, err error) {

	h, err := scrypt.Key([]byte(password), []byte(salt), 16384, 8, 1, PasswordHashBytes)
	if err != nil {

		return "", errors.New("error: failed to generate password hash")
	}

	return fmt.Sprintf("%x", h), nil
}

func Query_user_report(username string) {
	sql := `select * from report where username = ?`
	rows, err := db.Query(sql, username)

	if err != nil {
		fmt.Println(err)
	}

	var report Report
	for rows.Next() {
		err = rows.Scan(&report.report_key, &report.username)

		if err != nil {
			fmt.Println(err)
		}

		fmt.Println(report.report_key)
	}
}

func Register(username, password, role string) error {
	if len(username) == 0 || len(password) == 0 {
		fmt.Println("error: username or password is empty")
		// return false
		return errors.New("error: username or password is empty")
	}

	// TODO: role 腳色
	if len(role) == 0 || (role != "member" && role != "admin") {
		fmt.Println("error: role is error")
		// return false
		return errors.New("error: role is error")
	}

	sql := `select * from user where username = ?`
	rows, err := db.Query(sql, username)
	// fmt.Println(rows)
	// fmt.Println(err)

	if err != nil {
		fmt.Println(err.Error())
		fmt.Println("error: query error")
		// return false
		return errors.New("error: query error")
	}

	// 讀取SQL資料
	var user User
	// 不知道為啥要用 for 包住才可以用
	for rows.Next() {
		err = rows.Scan(&user.username, &user.password, &user.salt, &user.role)
	}

	if err != nil {
		fmt.Println("error: query error")
		fmt.Println(err)
		// return false
		return errors.New("error: query error")
	}
	// fmt.Println(user.username)

	if user.username == username {
		fmt.Println("error: username exist")
		// return false
		return errors.New("error: username exist")
	}

	//generate salt
	saltKey, err := GenerateSalt()
	if err != nil {
		// logs.Info(err.Error())
		fmt.Println("error: generate salt error")
		// return nil, http.StatusBadRequest, err
		// return false
		return errors.New("error: generate salt error")
	}

	// generate password hash
	hash, err := GeneratePassHash(password, saltKey)
	if err != nil {
		// logs.Info(err.Error())
		fmt.Println("error: generate hash error")
		// return nil, http.StatusBadRequest,err
		// return false
		return errors.New("error: generate hash error")
	}

	sql = `INSERT INTO user(username, password, salt, role) values(?, ?, ?, ?);`
	_, err = db.Query(sql, username, hash, saltKey, role)
	if err != nil {
		fmt.Println("error: query error")
		fmt.Println(err)
		// return false
		return errors.New("error: query error")
	}
	return nil
}

func Generate_report(username, report_key string) error {


	return nil
}
