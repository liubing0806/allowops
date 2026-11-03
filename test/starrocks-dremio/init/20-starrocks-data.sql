-- 仅在表为空时由 up.sh 执行。数据由确定性表达式生成。
INSERT INTO demo_dw.dim_user
SELECT g, concat('user_', g), split('Beijing,Shanghai,Shenzhen,Hangzhou,Chengdu', ',')[CAST(1 + g % 5 AS INT)],
       1 + g % 4, date_add('2024-01-01', INTERVAL (g % 700) DAY)
FROM (SELECT generate_series AS g FROM TABLE(generate_series(1, 10000))) t;

INSERT INTO demo_dw.dim_product
SELECT g, concat('product_', g), split('food,drink,toy,book,tool,cloth,phone,home', ',')[CAST(1 + g % 8 AS INT)],
       CAST(5 + (g * 37 % 9000) / 10.0 AS DECIMAL(10, 2)), CAST(20 + (g % 50) * 10 AS DECIMAL(12, 2))
FROM (SELECT generate_series AS g FROM TABLE(generate_series(1, 1000))) t;

INSERT INTO demo_dw.fact_orders
SELECT g, date_add('2026-01-01', INTERVAL (g % 180) DAY),
       1 + (g * 7919) % 10000, 1 + (g * 104729) % 1000, 1 + g % 50, 1 + g % 5,
       CAST(10 + ((g * 31) % 99000) / 100.0 AS DECIMAL(12, 2)),
       split('PAID,SHIPPED,DONE,CANCEL', ',')[CAST(1 + g % 4 AS INT)],
       concat('{"id":', g, ',"channel":"', split('app,web,mini', ',')[CAST(1 + g % 3 AS INT)], '","note":"', repeat('x', 200), '"}')
FROM (SELECT generate_series AS g FROM TABLE(generate_series(1, 500000))) t;
