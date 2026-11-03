-- 仅在审计表为空时由 up.sh 执行：200 条合成审计行，覆盖 EOF/ERR 状态、慢查询和内存超限。
INSERT INTO starrocks_audit_db__.starrocks_audit_tbl__
SELECT concat('00000000-0000-4000-8000-', lpad(CAST(g AS VARCHAR), 12, '0')),
       date_sub(now(), INTERVAL (g * 7) MINUTE),
       IF(g % 10 = 0, 'slow_query', 'query'),
       '127.0.0.1',
       split('allowops_query,dremio_ro,etl_demo', ',')[CAST(1 + g % 3 AS INT)],
       concat('''', split('allowops_query,dremio_ro,etl_demo', ',')[CAST(1 + g % 3 AS INT)], '''@''%'''),
       'default_wg', 'default_catalog', 'demo_dw',
       IF(g % 17 = 0, 'ERR', 'EOF'),
       IF(g % 17 = 0, IF(g % 34 = 0, 'MEM_LIMIT_EXCEEDED', 'ANALYSIS_ERROR'), ''),
       IF(g % 10 = 0, 12000 + g * 40, 20 + g % 300),
       (g % 40) * 1048576, (g % 40) * 100000, g % 500,
       (g % 30) * 1000000, (g % 25) * 1048576,
       g, 1, 'sr-fe',
       concat('SELECT /* synthetic */ count(*) FROM demo_dw.fact_orders WHERE store_id = ', g % 50),
       lpad(CAST(g % 20 AS VARCHAR), 32, '0'),
       0, 0, 0, NULL, NULL, 'default_warehouse'
FROM (SELECT generate_series AS g FROM TABLE(generate_series(1, 200))) t;
