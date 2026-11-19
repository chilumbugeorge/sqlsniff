/*!40101 SET NAMES utf8mb4 */;
-- comment with 'quote and (paren
# hash comment; with semicolon
SET FOREIGN_KEY_CHECKS = 0;
CREATE DATABASE IF NOT EXISTS app CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE app;
CREATE TABLE IF NOT EXISTS `order items` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'pk, with comma (and paren',
  `order_id` BIGINT UNSIGNED NOT NULL,
  `sku` VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '',
  `qty` INT UNSIGNED NOT NULL DEFAULT '1',
  `price` DECIMAL(12, 2) NOT NULL DEFAULT 0.00,
  `status` VARCHAR(16) NOT NULL DEFAULT 'new' CHECK (`status` IN ('new','paid')),
  `is_gift` BOOLEAN NOT NULL DEFAULT FALSE,
  `flag` BIT(1) NOT NULL DEFAULT b'0',
  `day` DATE NOT NULL,
  `at` TIME NULL,
  `yr` YEAR NULL,
  `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `total` DECIMAL(14,2) AS (`qty` * `price`) VIRTUAL,
  `hash` BINARY(16) NOT NULL,
  `raw` VARBINARY(128) NULL,
  `note` TINYTEXT,
  `loc` POINT NULL,
  `date` DATE NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_order_sku` (`order_id`, `sku`(32)),
  KEY `idx_created` (`created_at` DESC),
  FULLTEXT KEY `ft_note` (`note`),
  CONSTRAINT `chk_qty` CHECK (`qty` > 0)
) ENGINE=InnoDB AUTO_INCREMENT=1000 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC COMMENT='order; items'
  PARTITION BY HASH (`id`) PARTITIONS 4;

CREATE TEMPORARY TABLE tmp_ids (id BIGINT UNSIGNED NOT NULL, PRIMARY KEY (id)) ENGINE=InnoDB;
CREATE TABLE copy_a LIKE `order items`;
CREATE TABLE copy_b (LIKE `order items`);
CREATE TABLE snap ENGINE=InnoDB AS SELECT id, sku FROM `order items`;
CREATE TABLE snap2 (id BIGINT UNSIGNED NOT NULL, PRIMARY KEY (id)) ENGINE=InnoDB SELECT id FROM tmp_ids;
create table lower_case (
    id bigint unsigned not null auto_increment primary key,
    name varchar(100) not null
) engine = innodb default charset = utf8mb4;

ALTER TABLE `order items`
  ADD COLUMN `memo` VARCHAR(200) NULL COMMENT 'add text here' AFTER `note`,
  ADD COLUMN IF NOT EXISTS `x` BIGINT NULL FIRST,
  MODIFY `qty` BIGINT UNSIGNED NOT NULL,
  CHANGE COLUMN `at` `at_time` TIME NULL,
  ALTER COLUMN `qty` SET DEFAULT 1,
  ADD UNIQUE INDEX `uq_x` (`x`),
  ADD PRIMARY KEY (`id`),
  DROP PRIMARY KEY,
  DROP FOREIGN KEY fk_old,
  DROP KEY `idx_created`,
  RENAME INDEX a TO b,
  RENAME TO `order_items`,
  ALGORITHM=INPLACE, LOCK=NONE;
ALTER TABLE order_items ENGINE=InnoDB, CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
ALTER TABLE order_items ADD PARTITION (PARTITION p5 VALUES LESS THAN (100));
ALTER TABLE order_items DROP COLUMN x;
CREATE INDEX idx_sku ON order_items (sku) ALGORITHM=INPLACE LOCK=NONE;
DROP INDEX idx_sku ON order_items;
DROP TEMPORARY TABLE IF EXISTS tmp_ids;
TRUNCATE TABLE snap;
RENAME TABLE snap TO snap_old, snap2 TO snap;
INSERT INTO order_items (order_id, sku) VALUES (1, 'create table x; drop table y'), (2, "say \"hi\" it's");
INSERT INTO order_items (order_id, sku)
SELECT order_id, sku FROM snap
ON DUPLICATE KEY
UPDATE sku = VALUES(sku);
REPLACE INTO snap (id, sku) VALUES (1, 'a');
UPDATE order_items SET sku = CONCAT(sku, '-x') WHERE id IN (SELECT id FROM snap);
DELETE FROM order_items WHERE id = 1;
(SELECT 1) UNION (SELECT 2);
WITH c AS (SELECT 1) SELECT * FROM c;
LOCK TABLES order_items WRITE;
UNLOCK TABLES;
SHOW CREATE TABLE order_items;
EXPLAIN SELECT * FROM order_items;
ANALYZE TABLE order_items;
GRANT SELECT ON app.* TO 'reader'@'%';
SET @x := 5, @@session.sql_mode = 'STRICT_ALL_TABLES';
SET FOREIGN_KEY_CHECKS = 1;
START TRANSACTION;
COMMIT;
