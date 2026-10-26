-- 合成库表：只含合成数据。供生成扫描、哈希连接、聚合、窗口、NESTLOOP 连接的 profile。
CREATE DATABASE IF NOT EXISTS demo_dw;

CREATE TABLE IF NOT EXISTS demo_dw.dim_user (
  user_id INT NOT NULL,
  user_name VARCHAR(64),
  city VARCHAR(32),
  level INT,
  created_date DATE
) DUPLICATE KEY(user_id)
DISTRIBUTED BY HASH(user_id) BUCKETS 4
PROPERTIES ("replication_num" = "1");

CREATE TABLE IF NOT EXISTS demo_dw.dim_product (
  product_id INT NOT NULL,
  product_name VARCHAR(64),
  category VARCHAR(32),
  price DECIMAL(10, 2),
  min_amount DECIMAL(12, 2)
) DUPLICATE KEY(product_id)
DISTRIBUTED BY HASH(product_id) BUCKETS 2
PROPERTIES ("replication_num" = "1");

CREATE TABLE IF NOT EXISTS demo_dw.fact_orders (
  order_id BIGINT NOT NULL,
  order_date DATE NOT NULL,
  user_id INT,
  product_id INT,
  store_id INT,
  qty INT,
  amount DECIMAL(12, 2),
  status VARCHAR(16),
  origin_data VARCHAR(1024)
) DUPLICATE KEY(order_id, order_date)
PARTITION BY date_trunc('month', order_date)
DISTRIBUTED BY HASH(order_id) BUCKETS 8
PROPERTIES ("replication_num" = "1");
