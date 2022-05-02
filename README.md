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
