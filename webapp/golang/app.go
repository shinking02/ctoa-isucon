package main

import (
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	gsm "github.com/bradleypeabody/gorilla-sessions-memcache"
	"github.com/go-chi/chi/v5"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
)

var (
	db             *sqlx.DB
	store          *gsm.MemcacheStore
	memcacheClient *memcache.Client
)

const (
	postsPerPage  = 20
	ISO8601Format = "2006-01-02T15:04:05-07:00"
	UploadLimit   = 10 * 1024 * 1024 // 10mb
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int       `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
}

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	Imgdata      []byte    `db:"imgdata"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	CommentCount int
	Comments     []Comment
	User         User
	CSRFToken    string
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	User      User
}

func init() {
	memdAddr := os.Getenv("ISUCONP_MEMCACHED_ADDRESS")
	if memdAddr == "" {
		memdAddr = "localhost:11211"
	}
	memcacheClient = memcache.New(memdAddr)
	store = gsm.NewMemcacheStore(memcacheClient, "iscogram_", []byte("sendagaya"))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

func dbInitialize() {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}
	
	// データベース初期化時にすべてのキャッシュをクリア
	memcacheClient.FlushAll()
	
	// 既存の画像をファイルシステムに移行
	migrateImagesToFileSystem()
}

func tryLogin(accountName, password string) *User {
	u := User{}
	err := db.Get(&u, "SELECT * FROM users WHERE account_name = ? AND del_flg = 0", accountName)
	if err != nil {
		return nil
	}

	if calculatePasshash(u.AccountName, password) == u.Passhash {
		return &u
	} else {
		return nil
	}
}

func validateUser(accountName, password string) bool {
	return regexp.MustCompile(`\A[0-9a-zA-Z_]{3,}\z`).MatchString(accountName) &&
		regexp.MustCompile(`\A[0-9a-zA-Z_]{6,}\z`).MatchString(password)
}

// 今回のGo実装では言語側のエスケープの仕組みが使えないのでOSコマンドインジェクション対策できない
// 取り急ぎPHPのescapeshellarg関数を参考に自前で実装
// cf: http://jp2.php.net/manual/ja/function.escapeshellarg.php
func escapeshellarg(arg string) string {
	return "'" + strings.Replace(arg, "'", "'\\''", -1) + "'"
}

func digest(src string) string {
	// opensslのバージョンによっては (stdin)= というのがつくので取る
	out, err := exec.Command("/bin/bash", "-c", `printf "%s" `+escapeshellarg(src)+` | openssl dgst -sha512 | sed 's/^.*= //'`).Output()
	if err != nil {
		log.Print(err)
		return ""
	}

	return strings.TrimSuffix(string(out), "\n")
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

// キャッシュヘルパー関数
func getCachedUser(userID int) (User, error) {
	key := fmt.Sprintf("user_%d", userID)
	item, err := memcacheClient.Get(key)
	if err == nil {
		var user User
		if json.Unmarshal(item.Value, &user) == nil {
			return user, nil
		}
	}
	
	// キャッシュにない場合はDBから取得
	user := User{}
	err = db.Get(&user, "SELECT * FROM users WHERE id = ?", userID)
	if err != nil {
		return user, err
	}
	
	// キャッシュに保存
	if data, err := json.Marshal(user); err == nil {
		memcacheClient.Set(&memcache.Item{
			Key:        key,
			Value:      data,
			Expiration: 3600, // 1時間
		})
	}
	
	return user, nil
}

func setCachedUser(user User) {
	key := fmt.Sprintf("user_%d", user.ID)
	if data, err := json.Marshal(user); err == nil {
		memcacheClient.Set(&memcache.Item{
			Key:        key,
			Value:      data,
			Expiration: 3600,
		})
	}
}

func deleteCachedUser(userID int) {
	key := fmt.Sprintf("user_%d", userID)
	memcacheClient.Delete(key)
}

type CachedPosts struct {
	Posts     []Post    `json:"posts"`
	CachedAt  time.Time `json:"cached_at"`
}

func getCachedIndexPosts() ([]Post, bool) {
	key := "index_posts"
	item, err := memcacheClient.Get(key)
	if err != nil {
		return nil, false
	}
	
	var cached CachedPosts
	if json.Unmarshal(item.Value, &cached) != nil {
		return nil, false
	}
	
	// 10分以内のキャッシュのみ有効
	if time.Since(cached.CachedAt) > 10*time.Minute {
		return nil, false
	}
	
	return cached.Posts, true
}

func setCachedIndexPosts(posts []Post) {
	key := "index_posts"
	cached := CachedPosts{
		Posts:    posts,
		CachedAt: time.Now(),
	}
	
	if data, err := json.Marshal(cached); err == nil {
		memcacheClient.Set(&memcache.Item{
			Key:        key,
			Value:      data,
			Expiration: 600, // 10分に延長
		})
	}
}

func deleteCachedIndexPosts() {
	memcacheClient.Delete("index_posts")
}

type UserStats struct {
	CommentCount   int `json:"comment_count"`
	PostCount      int `json:"post_count"`
	CommentedCount int `json:"commented_count"`
}

func getCachedUserStats(userID int) (UserStats, bool) {
	key := fmt.Sprintf("user_stats_%d", userID)
	item, err := memcacheClient.Get(key)
	if err != nil {
		return UserStats{}, false
	}
	
	var stats UserStats
	if json.Unmarshal(item.Value, &stats) != nil {
		return UserStats{}, false
	}
	
	return stats, true
}

func setCachedUserStats(userID int, stats UserStats) {
	key := fmt.Sprintf("user_stats_%d", userID)
	if data, err := json.Marshal(stats); err == nil {
		memcacheClient.Set(&memcache.Item{
			Key:        key,
			Value:      data,
			Expiration: 1800, // 30分
		})
	}
}

func deleteCachedUserStats(userID int) {
	key := fmt.Sprintf("user_stats_%d", userID)
	memcacheClient.Delete(key)
}

func getCachedUserPosts(userID int) ([]Post, bool) {
	key := fmt.Sprintf("user_posts_%d", userID)
	item, err := memcacheClient.Get(key)
	if err != nil {
		return nil, false
	}
	
	var cached CachedPosts
	if json.Unmarshal(item.Value, &cached) != nil {
		return nil, false
	}
	
	// 10分以内のキャッシュのみ有効
	if time.Since(cached.CachedAt) > 10*time.Minute {
		return nil, false
	}
	
	return cached.Posts, true
}

func setCachedUserPosts(userID int, posts []Post) {
	key := fmt.Sprintf("user_posts_%d", userID)
	cached := CachedPosts{
		Posts:    posts,
		CachedAt: time.Now(),
	}
	
	if data, err := json.Marshal(cached); err == nil {
		memcacheClient.Set(&memcache.Item{
			Key:        key,
			Value:      data,
			Expiration: 600, // 10分
		})
	}
}

func deleteCachedUserPosts(userID int) {
	key := fmt.Sprintf("user_posts_%d", userID)
	memcacheClient.Delete(key)
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isuconp-go.session")

	return session
}

func getSessionUser(r *http.Request) User {
	session := getSession(r)
	uid, ok := session.Values["user_id"]
	if !ok || uid == nil {
		return User{}
	}

	// セッションからユーザー情報を取得を試みる
	if cachedUser, ok := session.Values["user_cache"]; ok {
		if user, ok := cachedUser.(User); ok && user.ID == uid {
			return user
		}
	}

	// memcachedからユーザー情報を取得
	if user, err := getCachedUser(uid.(int)); err == nil {
		// セッションにもキャッシュ
		session.Values["user_cache"] = user
		session.Save(r, nil)
		return user
	}

	// キャッシュにない場合は空のユーザーを返す（エラーログは出力済み）
	return User{}
}

func getFlash(w http.ResponseWriter, r *http.Request, key string) string {
	session := getSession(r)
	value, ok := session.Values[key]

	if !ok || value == nil {
		return ""
	} else {
		delete(session.Values, key)
		session.Save(r, w)
		return value.(string)
	}
}

func makePosts(results []Post, csrfToken string, allComments bool) ([]Post, error) {
	var posts []Post
	
	if len(results) == 0 {
		return posts, nil
	}

	// 投稿IDを収集
	postIDs := make([]int, len(results))
	for i, p := range results {
		postIDs[i] = p.ID
	}

	// プレースホルダーを作成
	placeholders := make([]string, len(postIDs))
	args := make([]interface{}, len(postIDs))
	for i, id := range postIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	placeholderStr := strings.Join(placeholders, ", ")

	// コメント数を一括取得
	commentCounts := make(map[int]int)
	commentCountQuery := fmt.Sprintf("SELECT post_id, COUNT(*) as count FROM comments WHERE post_id IN (%s) GROUP BY post_id", placeholderStr)
	rows, err := db.Query(commentCountQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	for rows.Next() {
		var postID, count int
		if err := rows.Scan(&postID, &count); err != nil {
			return nil, err
		}
		commentCounts[postID] = count
	}

	// コメントを一括取得（JOINでユーザー情報も取得）
	commentsMap := make(map[int][]Comment)
	commentQuery := fmt.Sprintf(`
		SELECT c.id, c.post_id, c.user_id, c.comment, c.created_at,
		       u.id, u.account_name, u.passhash, u.authority, u.del_flg, u.created_at
		FROM comments c 
		JOIN users u ON c.user_id = u.id 
		WHERE c.post_id IN (%s) 
		ORDER BY c.post_id, c.created_at DESC`, placeholderStr)
	
	commentRows, err := db.Query(commentQuery, args...)
	if err != nil {
		return nil, err
	}
	defer commentRows.Close()
	
	for commentRows.Next() {
		var comment Comment
		var user User
		err := commentRows.Scan(
			&comment.ID, &comment.PostID, &comment.UserID, &comment.Comment, &comment.CreatedAt,
			&user.ID, &user.AccountName, &user.Passhash, &user.Authority, &user.DelFlg, &user.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		comment.User = user
		commentsMap[comment.PostID] = append(commentsMap[comment.PostID], comment)
	}

	// 投稿のユーザー情報を一括取得
	userIDs := make([]int, len(results))
	for i, p := range results {
		userIDs[i] = p.UserID
	}
	
	// 重複を除去
	userIDSet := make(map[int]bool)
	uniqueUserIDs := []int{}
	for _, id := range userIDs {
		if !userIDSet[id] {
			userIDSet[id] = true
			uniqueUserIDs = append(uniqueUserIDs, id)
		}
	}
	
	userPlaceholders := make([]string, len(uniqueUserIDs))
	userArgs := make([]interface{}, len(uniqueUserIDs))
	for i, id := range uniqueUserIDs {
		userPlaceholders[i] = "?"
		userArgs[i] = id
	}
	userPlaceholderStr := strings.Join(userPlaceholders, ", ")
	
	usersMap := make(map[int]User)
	userQuery := fmt.Sprintf("SELECT id, account_name, passhash, authority, del_flg, created_at FROM users WHERE id IN (%s)", userPlaceholderStr)
	userRows, err := db.Query(userQuery, userArgs...)
	if err != nil {
		return nil, err
	}
	defer userRows.Close()
	
	for userRows.Next() {
		var user User
		err := userRows.Scan(&user.ID, &user.AccountName, &user.Passhash, &user.Authority, &user.DelFlg, &user.CreatedAt)
		if err != nil {
			return nil, err
		}
		usersMap[user.ID] = user
	}

	// 投稿データを組み立て
	for _, p := range results {
		p.CommentCount = commentCounts[p.ID]
		
		// コメントを設定（制限あり/なし）
		comments := commentsMap[p.ID]
		if !allComments && len(comments) > 3 {
			comments = comments[:3]
		}
		
		// コメントの順序を逆転（古い順にする）
		for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
			comments[i], comments[j] = comments[j], comments[i]
		}
		p.Comments = comments
		
		// ユーザー情報を設定
		p.User = usersMap[p.UserID]
		p.CSRFToken = csrfToken

		if p.User.DelFlg == 0 {
			posts = append(posts, p)
		}
		if len(posts) >= postsPerPage {
			break
		}
	}

	return posts, nil
}

func imageURL(p Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
}

func isLogin(u User) bool {
	return u.ID != 0
}

func getCSRFToken(r *http.Request) string {
	session := getSession(r)
	csrfToken, ok := session.Values["csrf_token"]
	if !ok {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := crand.Read(k); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(w http.ResponseWriter, r *http.Request) {
	dbInitialize()
	w.WriteHeader(http.StatusOK)
}

func getLogin(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	if isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("login.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{me, getFlash(w, r, "notice")})
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.FormValue("account_name"), r.FormValue("password"))

	if u != nil {
		// ログイン成功時にユーザー情報をキャッシュ
		setCachedUser(*u)
		
		session := getSession(r)
		session.Values["user_id"] = u.ID
		session.Values["user_cache"] = *u
		session.Values["csrf_token"] = secureRandomStr(16)
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values["notice"] = "アカウント名かパスワードが間違っています"
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("register.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{User{}, getFlash(w, r, "notice")})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(r)
		session.Values["notice"] = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.Get(&exists, "SELECT 1 FROM users WHERE `account_name` = ?", accountName)

	if exists == 1 {
		session := getSession(r)
		session.Values["notice"] = "アカウント名がすでに使われています"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	query := "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)"
	result, err := db.Exec(query, accountName, calculatePasshash(accountName, password))
	if err != nil {
		log.Print(err)
		return
	}

	session := getSession(r)
	uid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}
	
	// 新しく作成されたユーザーをキャッシュ
	newUser := User{
		ID:          int(uid),
		AccountName: accountName,
		Passhash:    calculatePasshash(accountName, password),
		Authority:   0,
		DelFlg:      0,
		CreatedAt:   time.Now(),
	}
	
	// memcachedにもキャッシュを保存
	setCachedUser(newUser)
	
	session.Values["user_id"] = uid
	session.Values["user_cache"] = newUser
	session.Values["csrf_token"] = secureRandomStr(16)
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	delete(session.Values, "user_id")
	delete(session.Values, "user_cache")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	// キャッシュから投稿を取得を試みる
	if cachedPosts, found := getCachedIndexPosts(); found {
		fmap := template.FuncMap{
			"imageURL": imageURL,
		}

		tmpl, err := template.New("layout.html").Funcs(fmap).ParseFiles(
			getTemplPath("layout.html"),
			getTemplPath("index.html"),
			getTemplPath("posts.html"),
			getTemplPath("post.html"),
		)
		if err != nil {
			log.Print("Template parse error (cached):", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		
		err = tmpl.Execute(w, struct {
			Posts     []Post
			Me        User
			CSRFToken string
			Flash     string
		}{cachedPosts, me, getCSRFToken(r), getFlash(w, r, "notice")})
		if err != nil {
			log.Print("Template execute error (cached):", err)
		}
		return
	}

	results := []Post{}

	err := db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` ORDER BY `created_at` DESC LIMIT ?", postsPerPage)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	// 投稿をキャッシュに保存
	setCachedIndexPosts(posts)

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	tmpl, err := template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("index.html"),
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	)
	if err != nil {
		log.Print("Template parse error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	
	err = tmpl.Execute(w, struct {
		Posts     []Post
		Me        User
		CSRFToken string
		Flash     string
	}{posts, me, getCSRFToken(r), getFlash(w, r, "notice")})
	if err != nil {
		log.Print("Template execute error:", err)
	}
}

func getAccountName(w http.ResponseWriter, r *http.Request) {
	accountName := r.PathValue("accountName")
	user := User{}

	err := db.Get(&user, "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0", accountName)
	if err != nil {
		log.Print(err)
		return
	}

	if user.ID == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// ユーザー情報をキャッシュに保存
	setCachedUser(user)

	// キャッシュからユーザーの投稿を取得を試みる
	var posts []Post
	if cachedPosts, found := getCachedUserPosts(user.ID); found {
		posts = cachedPosts
	} else {
		results := []Post{}
		err = db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC LIMIT ?", user.ID, postsPerPage)
		if err != nil {
			log.Print(err)
			return
		}

		posts, err = makePosts(results, getCSRFToken(r), false)
		if err != nil {
			log.Print(err)
			return
		}

		// ユーザーの投稿をキャッシュに保存
		setCachedUserPosts(user.ID, posts)
	}

	// キャッシュから統計情報を取得を試みる
	var stats UserStats
	if cachedStats, found := getCachedUserStats(user.ID); found {
		stats = cachedStats
	} else {
		// 統計情報を一度のクエリで取得
		statsQuery := `
			SELECT 
				(SELECT COUNT(*) FROM comments WHERE user_id = ?) as comment_count,
				(SELECT COUNT(*) FROM posts WHERE user_id = ?) as post_count,
				(SELECT COUNT(*) FROM comments WHERE post_id IN (SELECT id FROM posts WHERE user_id = ?)) as commented_count
		`
		
		err = db.Get(&stats, statsQuery, user.ID, user.ID, user.ID)
		if err != nil {
			log.Print(err)
			return
		}

		// 統計情報をキャッシュに保存
		setCachedUserStats(user.ID, stats)
	}

	me := getSessionUser(r)

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("user.html"),
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	)).Execute(w, struct {
		Posts          []Post
		User           User
		PostCount      int
		CommentCount   int
		CommentedCount int
		Me             User
	}{posts, user, stats.PostCount, stats.CommentCount, stats.CommentedCount, me})
}

func getPosts(w http.ResponseWriter, r *http.Request) {
	m, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Print(err)
		return
	}
	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}

	t, err := time.Parse(ISO8601Format, maxCreatedAt)
	if err != nil {
		log.Print(err)
		return
	}

	results := []Post{}
	err = db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `created_at` <= ? ORDER BY `created_at` DESC LIMIT ?", t.Format(ISO8601Format), postsPerPage)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("posts.html").Funcs(fmap).ParseFiles(
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	)).Execute(w, posts)
}

func getPostsID(w http.ResponseWriter, r *http.Request) {
	pidStr := r.PathValue("id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}
	err = db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `id` = ?", pid)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), true)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	p := posts[0]

	me := getSessionUser(r)

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("post_id.html"),
		getTemplPath("post.html"),
	)).Execute(w, struct {
		Post Post
		Me   User
	}{p, me})
}

func postIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		session := getSession(r)
		session.Values["notice"] = "画像が必須です"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	mime := ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := header.Header["Content-Type"][0]
		if strings.Contains(contentType, "jpeg") {
			mime = "image/jpeg"
		} else if strings.Contains(contentType, "png") {
			mime = "image/png"
		} else if strings.Contains(contentType, "gif") {
			mime = "image/gif"
		} else {
			session := getSession(r)
			session.Values["notice"] = "投稿できる画像形式はjpgとpngとgifだけです"
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	filedata, err := io.ReadAll(file)
	if err != nil {
		log.Print(err)
		return
	}

	if len(filedata) > UploadLimit {
		session := getSession(r)
		session.Values["notice"] = "ファイルサイズが大きすぎます"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// 画像データなしでポストを作成
	query := "INSERT INTO `posts` (`user_id`, `mime`, `body`) VALUES (?,?,?)"
	result, err := db.Exec(
		query,
		me.ID,
		mime,
		r.FormValue("body"),
	)
	if err != nil {
		log.Print(err)
		return
	}

	pid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}

	// 画像をファイルシステムに保存
	err = saveImageToFile(int(pid), mime, filedata)
	if err != nil {
		log.Print("Failed to save image file:", err)
		// ファイル保存に失敗した場合は投稿を削除
		db.Exec("DELETE FROM posts WHERE id = ?", pid)
		session := getSession(r)
		session.Values["notice"] = "画像の保存に失敗しました"
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// 新しい投稿が作成されたのでキャッシュを無効化
	deleteCachedIndexPosts()
	deleteCachedUserPosts(me.ID)
	deleteCachedUserStats(me.ID)

	http.Redirect(w, r, "/posts/"+strconv.FormatInt(pid, 10), http.StatusFound)
}

func getImage(w http.ResponseWriter, r *http.Request) {
	pidStr := r.PathValue("id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	ext := r.PathValue("ext")
	
	// ファイルシステムから画像を読み込み（DBアクセスを完全に削除）
	filename := fmt.Sprintf("../public/images/%d.%s", pid, ext)
	imageData, err := os.ReadFile(filename)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Content-Typeを設定
	mime := ""
	switch ext {
	case "jpg":
		mime = "image/jpeg"
	case "png":
		mime = "image/png"
	case "gif":
		mime = "image/gif"
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", mime)
	w.Header().Set("Cache-Control", "public, max-age=86400") // 1日キャッシュ
	_, err = w.Write(imageData)
	if err != nil {
		log.Print(err)
		return
	}
}

func postComment(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	postID, err := strconv.Atoi(r.FormValue("post_id"))
	if err != nil {
		log.Print("post_idは整数のみです")
		return
	}

	query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)"
	_, err = db.Exec(query, postID, me.ID, r.FormValue("comment"))
	if err != nil {
		log.Print(err)
		return
	}

	// コメントが追加されたので関連するキャッシュを無効化
	deleteCachedIndexPosts()
	deleteCachedUserStats(me.ID)
	
	// 投稿者の統計情報も無効化（コメントされた数が変わる）
	var post Post
	if err := db.Get(&post, "SELECT user_id FROM posts WHERE id = ?", postID); err == nil {
		deleteCachedUserStats(post.UserID)
	}

	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	users := []User{}
	err := db.Select(&users, "SELECT id, account_name, authority, del_flg, created_at FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		log.Print(err)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("banned.html")),
	).Execute(w, struct {
		Users     []User
		Me        User
		CSRFToken string
	}{users, me, getCSRFToken(r)})
}

func postAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	query := "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?"

	err := r.ParseForm()
	if err != nil {
		log.Print(err)
		return
	}

	for _, id := range r.Form["uid[]"] {
		db.Exec(query, 1, id)
		// BANされたユーザーのキャッシュを無効化
		if userID, err := strconv.Atoi(id); err == nil {
			deleteCachedUser(userID)
			deleteCachedUserPosts(userID)
			deleteCachedUserStats(userID)
		}
	}

	// BANによってインデックスページの表示も変わる可能性があるため無効化
	deleteCachedIndexPosts()

	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

// 画像保存用のヘルパー関数
func saveImageToFile(postID int, mime string, data []byte) error {
	ext := ""
	if mime == "image/jpeg" {
		ext = ".jpg"
	} else if mime == "image/png" {
		ext = ".png"
	} else if mime == "image/gif" {
		ext = ".gif"
	}

	filename := fmt.Sprintf("../public/images/%d%s", postID, ext)
	return os.WriteFile(filename, data, 0644)
}

func imageFileExists(postID int, mime string) bool {
	ext := ""
	if mime == "image/jpeg" {
		ext = ".jpg"
	} else if mime == "image/png" {
		ext = ".png"
	} else if mime == "image/gif" {
		ext = ".gif"
	}

	filename := fmt.Sprintf("../public/images/%d%s", postID, ext)
	_, err := os.Stat(filename)
	return err == nil
}

// 既存の画像データをファイルシステムに移行
func migrateImagesToFileSystem() {
	log.Println("Migrating images to file system...")
	
	posts := []Post{}
	err := db.Select(&posts, "SELECT id, mime, imgdata FROM posts WHERE imgdata IS NOT NULL LIMIT 1000")
	if err != nil {
		log.Print("Failed to select posts for migration:", err)
		return
	}

	migrated := 0
	for _, post := range posts {
		if !imageFileExists(post.ID, post.Mime) {
			err := saveImageToFile(post.ID, post.Mime, post.Imgdata)
			if err != nil {
				log.Printf("Failed to migrate image for post %d: %v", post.ID, err)
			} else {
				migrated++
			}
		}
	}
	
	log.Printf("Migrated %d images to file system", migrated)
}

func main() {
	host := os.Getenv("ISUCONP_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("ISUCONP_DB_PORT")
	if port == "" {
		port = "3306"
	}
	_, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local",
		user,
		password,
		host,
		port,
		dbname,
	)

	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	defer db.Close()

	// データベース接続プールの設定
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	// 既存の画像をファイルシステムに移行（起動時に一度だけ実行）
	go migrateImagesToFileSystem()

	r := chi.NewRouter()

	r.Get("/initialize", getInitialize)
	r.Get("/login", getLogin)
	r.Post("/login", postLogin)
	r.Get("/register", getRegister)
	r.Post("/register", postRegister)
	r.Get("/logout", getLogout)
	r.Get("/", getIndex)
	r.Get("/posts", getPosts)
	r.Get("/posts/{id}", getPostsID)
	r.Post("/", postIndex)
	r.Get("/image/{id}.{ext}", getImage)
	r.Post("/comment", postComment)
	r.Get("/admin/banned", getAdminBanned)
	r.Post("/admin/banned", postAdminBanned)
	r.Get(`/@{accountName:[a-zA-Z]+}`, getAccountName)
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir("../public")).ServeHTTP(w, r)
	})

	log.Fatal(http.ListenAndServe(":8080", r))
}