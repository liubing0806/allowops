-- 镜像只带内置审计日志插件（SHOW PLUGINS 只有 __builtin_AuditLogBuilder），没有 AuditLoader。
-- 按 StarRocks 3.3 文档的 AuditLoader 默认结构手工建表，并写入合成审计行。
CREATE DATABASE IF NOT EXISTS starrocks_audit_db__;

CREATE TABLE IF NOT EXISTS starrocks_audit_db__.starrocks_audit_tbl__ (
  `queryId` VARCHAR(64) COMMENT "查询的唯一ID",
  `timestamp` DATETIME NOT NULL COMMENT "查询开始时间",
  `queryType` VARCHAR(12) COMMENT "查询类型（query, slow_query, connection）",
  `clientIp` VARCHAR(32) COMMENT "客户端IP",
  `user` VARCHAR(64) COMMENT "查询用户名",
  `authorizedUser` VARCHAR(64) COMMENT "用户唯一标识，既user_identity",
  `resourceGroup` VARCHAR(64) COMMENT "资源组名",
  `catalog` VARCHAR(32) COMMENT "数据目录名",
  `db` VARCHAR(96) COMMENT "查询所在数据库",
  `state` VARCHAR(8) COMMENT "查询状态（EOF，ERR，OK）",
  `errorCode` VARCHAR(512) COMMENT "错误码",
  `queryTime` BIGINT COMMENT "查询执行时间（毫秒）",
  `scanBytes` BIGINT COMMENT "查询扫描的字节数",
  `scanRows` BIGINT COMMENT "查询扫描的记录行数",
  `returnRows` BIGINT COMMENT "查询返回的结果行数",
  `cpuCostNs` BIGINT COMMENT "查询CPU耗时（纳秒）",
  `memCostBytes` BIGINT COMMENT "查询消耗内存（字节）",
  `stmtId` INT COMMENT "SQL语句增量ID",
  `isQuery` TINYINT COMMENT "SQL是否为查询（1或0）",
  `feIp` VARCHAR(128) COMMENT "执行该语句的FE IP",
  `stmt` VARCHAR(1048576) COMMENT "SQL原始语句",
  `digest` VARCHAR(32) COMMENT "慢SQL指纹",
  `planCpuCosts` DOUBLE COMMENT "查询规划阶段CPU占用（纳秒）",
  `planMemCosts` DOUBLE COMMENT "查询规划阶段内存占用（字节）",
  `pendingTimeMs` BIGINT COMMENT "查询在队列中等待的时间（毫秒）",
  `candidateMVs` VARCHAR(65533) NULL COMMENT "候选MV列表",
  `hitMvs` VARCHAR(65533) NULL COMMENT "命中MV列表",
  `warehouse` VARCHAR(32) NULL COMMENT "仓库名称"
) ENGINE = OLAP
DUPLICATE KEY (`queryId`, `timestamp`, `queryType`)
COMMENT "Audit log table"
PARTITION BY date_trunc('day', `timestamp`)
PROPERTIES (
  "replication_num" = "1",
  "partition_live_number" = "30"
);
