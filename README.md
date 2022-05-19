# Getting Started
## 1. 更新 golang 到 1.18
- https://go.dev/doc/install
## 2. 匯入 MySQL 資料
- 安裝 MYSQL
- 建立 database `go_demo`
  - `$mysql -u root -p`
  - `mysql> create databases go_demo;`
- 建立 user `go_user` 密碼為 `123123`
	- `mysql> CREATE USER 'go_user'@'localhost' IDENTIFIED BY '123123';`
- 給予權限讀取資料庫
	- `mysql> GRANT ALL PRIVILEGES ON go_demo.* TO 'go_user'@'localhost';`
	- `mysql> FLUSH PRIVILEGES;`
	- `mysql> quit`
- 匯入資料 
  - `$mysql -u root -p go_demo < init_backup.sql`
## 3. .env
```
SQL_USERNAME=
SQL_PASSWORD=
SQL_SERVER_IP=
SQL_SERVER_PORT=
SQL_DATABASE=
SECRET_KEY=
```
## 4. start 
- `$go run .`

---

# 備份 couchDB
- couchDB 預設為 5984 port
- 請替換下列指令參數
  - username：couchDB 帳號
  - password：couchDB 密碼
  - database：指定的 database
- 切換目錄
	```shell
	cd backup
	```
## 從 database 匯出資料
```shell
curl --user <username>:<password> -X GET http://127.0.0.1:5984/<database>/_all_docs?include_docs=true > db.json
```
## 匯入資料至指定的 database

匯出的 db.json 需先轉換
```shell
node transformdocs.js
```
匯入至 database
```shell
curl --user <username>:<password> -d @db_u.json -H "Content-Type: application/json" -X POST http://127.0.0.1:5984/<database>/_bulk_docs
```