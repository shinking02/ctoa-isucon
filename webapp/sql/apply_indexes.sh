#!/bin/bash

# データベース接続設定
DB_HOST=${ISUCONP_DB_HOST:-localhost}
DB_PORT=${ISUCONP_DB_PORT:-3306}
DB_USER=${ISUCONP_DB_USER:-root}
DB_NAME=${ISUCONP_DB_NAME:-isuconp}
DB_PASSWORD=${ISUCONP_DB_PASSWORD:-}

# パスワードオプションの設定
PASSWORD_OPTION=""
if [ -n "$DB_PASSWORD" ]; then
    PASSWORD_OPTION="-p$DB_PASSWORD"
fi

echo "インデックスを適用中..."

# インデックス追加SQLを実行
mysql -h $DB_HOST -P $DB_PORT -u $DB_USER $PASSWORD_OPTION $DB_NAME < add_indexes.sql

if [ $? -eq 0 ]; then
    echo "インデックスの適用が完了しました。"
else
    echo "インデックスの適用に失敗しました。"
    exit 1
fi

# インデックスの確認
echo "現在のインデックス一覧:"
mysql -h $DB_HOST -P $DB_PORT -u $DB_USER $PASSWORD_OPTION $DB_NAME -e "
SHOW INDEX FROM users;
SHOW INDEX FROM posts;
SHOW INDEX FROM comments;
" 