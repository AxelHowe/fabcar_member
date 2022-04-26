## Getting Started
1. 更新 golang 到 1.18
2. 匯入 MySQL 資料
	- 建立 database `go_demo`
		- `$mysql -u root -p`
		- `mysql> create databases go_demo;`
	- 匯入資料 
		- `$mysql -u root -p < init_backup.sql`
1. .env
```
SQL_USERNAME=
SQL_PASSWORD=
SQL_SERVER_IP=
SQL_SERVER_PORT=
SQL_DATABASE=
SECRET_KEY=
```