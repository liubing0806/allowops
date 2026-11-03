# StarRocks + Dremio 本地集成测试环境

用于 allowops 的 `starrocks_*`、`dremio_*` 内置处理器的本地集成测试。只在本机 Docker 运行，端口只绑定 127.0.0.1，不进入 GitHub CI。

镜像不在本目录定义。`up.sh` 从本目录的 `images.env` 读取 `SR_FE_IMAGE`、`SR_BE_IMAGE`、`DREMIO_IMAGE`（该文件不入库，格式见 `images.env.example`；可用环境变量 `IMAGES_ENV` 指定其他文件）。本地验证使用的是 StarRocks 3.3.22 和 Dremio 24.1 的定制构建，官方镜像未验证。

## 使用

```bash
test/starrocks-dremio/up.sh      # 启动、注册 BE、写入合成数据、创建账号和 Dremio 数据源（幂等）
test/starrocks-dremio/down.sh    # 删除本项目的容器、卷、网络和 .state
```

| 服务 | 地址 |
| --- | --- |
| StarRocks FE MySQL | `127.0.0.1:29030` |
| StarRocks FE HTTP | `127.0.0.1:28030` |
| Dremio REST | `http://127.0.0.1:29047` |

Dremio 的 ZooKeeper 是同一 Dremio 镜像内 `zookeeper-3.7.2.jar` 启动的单节点实例（该构建不启动内置 ZooKeeper），不暴露端口。

## 账号

密码在 `up.sh` 运行时随机生成，保存在 `.state/credentials.json` 和 `.state/sr-*.cnf`（目录 0700、文件 0600，已加入 .gitignore）。不要把密码放进命令行参数。

| 账号 | 用途 |
| --- | --- |
| StarRocks `root` | 初始化和排错 |
| `allowops_query` | 只有 `demo_dw` 的 SELECT，对应 `starrocks_query` |
| `allowops_diag` | `demo_dw`、审计库的 SELECT 加 SYSTEM 级 OPERATE，对应 `starrocks_diag` |
| `dremio_ro` | Dremio 数据源 `starrocks` 使用，只有 SELECT |
| `dremio_rw` | Dremio 数据源 `starrocks-scratch` 使用，只在 `scratch` 库可写，用于核实 `external_query` 能否写入 |
| Dremio `allowops_admin`、`allowops_reader` | 首用户和普通用户（两者权限相同） |

## 工具

```bash
test/starrocks-dremio/sr.sh query -e 'SELECT count(*) FROM demo_dw.fact_orders'
test/starrocks-dremio/dremio.py GET /apiv2/server_status
```

`sr.sh <root|query|diag|dremio_ro|dremio_rw>` 通过选项文件连接 FE。`dremio.py [--role admin|user] METHOD PATH [--data ...]` 登录后发送 REST 请求。

## 合成数据

- `demo_dw.fact_orders`：50 万行，按月分区；`dim_user` 1 万行；`dim_product` 1000 行。
- `starrocks_audit_db__.starrocks_audit_tbl__`：镜像没有 AuditLoader 插件，按其默认结构手工建表并写入 200 行合成记录。
- `scratch.t_write_probe`：只供 `dremio_rw` 写入探测。
