// sqlrun 用 go-sql-driver/mysql（与 allowops 的 mysql_query 相同的驱动）在同一会话中依次执行多条语句，
// 打印耗时、结果行（TSV）和服务端错误码。账号取自 .state/credentials.json，密码不出现在命令行。
//
// 用法：go run ./test/starrocks-dremio/tools/sqlrun -as query -- 'SET query_timeout=2' 'SELECT sleep(5)'
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

func main() {
	as := flag.String("as", "query", "StarRocks 账号：root|query|diag|dremio_ro|dremio_rw")
	addr := flag.String("addr", "127.0.0.1:29030", "FE MySQL 地址")
	state := flag.String("state", "test/starrocks-dremio/.state", "凭据目录")
	maxRows := flag.Int("rows", 10, "每条语句最多打印的行数")
	multi := flag.Bool("multi", false, "启用 multiStatements（一次发送多条语句）")
	rawMode := flag.Bool("raw", false, "只输出最后一条语句的第一列（每行一个值，不带表头和统计），用于保存 profile/EXPLAIN 文本")
	flag.Parse()

	raw, err := os.ReadFile(filepath.Join(*state, "credentials.json"))
	if err != nil {
		fatal(err)
	}
	var creds map[string]struct{ UserName, Password string }
	if err := json.Unmarshal(raw, &creds); err != nil {
		fatal(err)
	}
	c, ok := creds["sr_"+*as]
	if !ok {
		fatal(fmt.Errorf("unknown account %q", *as))
	}
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net, cfg.Addr = c.UserName, c.Password, "tcp", *addr
	cfg.MultiStatements = *multi
	cfg.Timeout = 10 * time.Second
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		fatal(err)
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		fatal(err)
	}
	defer conn.Close()

	args := flag.Args()
	for i, stmt := range args {
		if *rawMode && i == len(args)-1 {
			rows, err := conn.QueryContext(ctx, stmt)
			if err != nil {
				report(err, 0)
				os.Exit(1)
			}
			for rows.Next() {
				var v sql.NullString
				if err := rows.Scan(&v); err != nil {
					fatal(err)
				}
				fmt.Println(v.String)
			}
			if err := rows.Err(); err != nil {
				report(err, 0)
				os.Exit(1)
			}
			rows.Close()
			return
		}
		if *rawMode {
			if _, err := conn.ExecContext(ctx, stmt); err != nil {
				report(err, 0)
				os.Exit(1)
			}
			continue
		}
		fmt.Printf("> %s\n", stmt)
		start := time.Now()
		rows, err := conn.QueryContext(ctx, stmt)
		if err != nil {
			report(err, time.Since(start))
			continue
		}
		cols, _ := rows.Columns()
		fmt.Println(strings.Join(cols, "\t"))
		n := 0
		for rows.Next() {
			vals := make([]sql.RawBytes, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				report(err, time.Since(start))
				break
			}
			n++
			if n <= *maxRows {
				out := make([]string, len(vals))
				for i, v := range vals {
					if v == nil {
						out[i] = "NULL"
					} else {
						out[i] = string(v)
					}
				}
				fmt.Println(strings.Join(out, "\t"))
			}
		}
		if err := rows.Err(); err != nil {
			report(err, time.Since(start))
		}
		rows.Close()
		fmt.Printf("-- rows=%d elapsed=%s\n", n, time.Since(start).Round(time.Millisecond))
	}
}

func report(err error, d time.Duration) {
	var me *mysql.MySQLError
	if errors.As(err, &me) {
		fmt.Printf("-- ERROR %d (%s) elapsed=%s: %s\n", me.Number, me.SQLState, d.Round(time.Millisecond), me.Message)
		return
	}
	fmt.Printf("-- ERROR (client) elapsed=%s: %v\n", d.Round(time.Millisecond), err)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "sqlrun:", err)
	os.Exit(1)
}
