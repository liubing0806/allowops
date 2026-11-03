# dremio_diag 测试样本

样本由 `test/starrocks-dremio/gen_dremio_diag_samples.py` 在本地 Dremio 24.1.0 上生成，内容是服务器的原始响应，只做下面的文本替换：

- 数据源名替换为 `demo_src`（只读）和 `demo_scratch`（可写）。
- Dremio 协议里含内部名称的字段名改写，例如 sys.nodes 的端口列 `peer_port`、profile 里的 `peerPort`。解析器不读取这些字段。

| 目录 | 内容 |
| --- | --- |
| `profiles/*.zip` | `POST /apiv2/support/{id}/download` 的 zip，重新打包以应用上述替换。每个 zip 对应一种查询形态 |
| `jobs/status_*.json` | `GET /api/v3/job/{id}` 的响应，加上 `id` |
| `jobs/listing.json` | `GET /apiv2/jobs-listing/v1.0` 的响应 |
| `jobs/index.json` | 形态名到作业 ID 的对应 |
| `sys/*.json` | `GET /api/v3/job/{id}/results` 对 `SELECT * FROM sys.nodes`、`sys.memory`、`sys.reflections` 的响应；`reflections` 在样本环境中为 0 行，只有列定义 |

## 查询形态与预期命中的规则

| 样本 | 形态 | 命中 |
| --- | --- | --- |
| `pushdown_scan` | 单表过滤，整条语句下推 | 无 |
| `pushdown_join_agg` | 同一数据源内的连接和聚合，整条语句下推 | 无 |
| `cross_join_small` | 跨数据源连接，两侧各 1 万行 | 无 |
| `cross_join_large` | 跨数据源连接，一侧 50 万行 | DR-SCAN-1、DR-JOIN-1 |
| `scan_large` | 读取 50 万行 | DR-SCAN-1 |
| `join_explosion` | 连接键只有 5 个取值，输出 2000 万行 | DR-JOIN-3 |
| `nested_loop` | 非等值连接 | DR-JOIN-2 |
| `many_branches` | 24 个分支的 UNION ALL | DR-PLAN-1、DR-SCAN-1、DR-MEM-1 |
| `failed_unknown_table` | 对象不存在，作业失败 | DR-FAIL-1 |
| `canceled` | 运行中被取消 | DR-FAIL-1 |

`many_branches` 的规划耗时占比随元数据缓存状态变化（本地多次生成为 25% 至 33%），样本固定后结果不变。

本环境的 Dremio 没有多实例的算子（JDBC 数据源的扫描宽度为 1，连接和聚合与扫描在同一个片段内），也不能创建反射（刷新作业报 `NodeStripper` 类加载失败），因此没有实例间倾斜和命中反射的样本。
