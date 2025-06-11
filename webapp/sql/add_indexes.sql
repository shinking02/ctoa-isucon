-- インデックス追加によるパフォーマンス最適化

-- usersテーブルのインデックス
-- ログイン時の検索用（account_name + del_flg）
CREATE INDEX idx_users_account_name_del_flg ON users (account_name, del_flg);

-- 削除フラグでの検索用
CREATE INDEX idx_users_del_flg ON users (del_flg);

-- postsテーブルのインデックス
-- 投稿一覧取得用（created_at降順）
CREATE INDEX idx_posts_created_at ON posts (created_at DESC);

-- ユーザー投稿取得用（user_id + created_at降順）
CREATE INDEX idx_posts_user_id_created_at ON posts (user_id, created_at DESC);

-- commentsテーブルのインデックス
-- 投稿のコメント取得用（post_id + created_at降順）
CREATE INDEX idx_comments_post_id_created_at ON comments (post_id, created_at DESC);

-- ユーザーコメント数取得用
CREATE INDEX idx_comments_user_id ON comments (user_id);

-- ユーザー統計（投稿へのコメント数）取得用
CREATE INDEX idx_comments_post_id ON comments (post_id);

-- 追加の最適化インデックス
-- 管理者機能用（authority + del_flg + created_at）
CREATE INDEX idx_users_authority_del_flg_created_at ON users (authority, del_flg, created_at DESC);

-- 時系列投稿検索用（created_at条件での絞り込み）
CREATE INDEX idx_posts_created_at_range ON posts (created_at, id DESC);

-- 複合検索用インデックス（posts）
CREATE INDEX idx_posts_user_id_created_at_id ON posts (user_id, created_at DESC, id); 