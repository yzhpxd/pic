package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	ConfigFile  = "./config.json"
	UploadDir   = "./uploads"
	MaxFileSize = 10 * 1024 * 1024 // 10MB
	ListenPort  = ":8080"
)

// 配置结构体
type Config struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var (
	appConfig Config
	cfgLock   sync.RWMutex
	currToken string
)

type ImageInfo struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Time string `json:"time"`
	Size int64  `json:"size"`
}

func initConfig() {
	if _, err := os.Stat(ConfigFile); os.IsNotExist(err) {
		appConfig = Config{
			Username: "Admin",
			Password: "Admin@123456", // 默认初始密码，可在网页后台直接修改
		}
		saveConfig(appConfig)
		log.Println("已自动生成默认配置文件 config.json (默认账号: admin / 密码: Admin@123456)")
	} else {
		data, err := os.ReadFile(ConfigFile)
		if err != nil {
			log.Fatalf("读取配置文件失败: %v", err)
		}
		if err := json.Unmarshal(data, &appConfig); err != nil {
			log.Fatalf("解析配置文件失败: %v", err)
		}
	}
}

func saveConfig(cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigFile, data, 0600)
}

func main() {
	initConfig()

	if err := os.MkdirAll(UploadDir, 0755); err != nil {
		log.Fatalf("创建上传目录失败: %v", err)
	}

	mux := http.NewServeMux()

	// 开放路由
	mux.HandleFunc("/login", handleLoginPage)
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/logout", handleLogout)

	// 受保护路由
	mux.HandleFunc("/", authMiddleware(handleIndex))
	mux.HandleFunc("/api/upload", authMiddleware(handleUpload))
	mux.HandleFunc("/api/list", authMiddleware(handleList))
	mux.HandleFunc("/api/delete", authMiddleware(handleDelete))
	mux.HandleFunc("/api/change-password", authMiddleware(handleChangePassword))

	// 图片静态路由
	fileServer := http.StripPrefix("/i/", http.FileServer(http.Dir(UploadDir)))
	mux.Handle("/i/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fileServer.ServeHTTP(w, r)
	}))

	fmt.Printf("图床服务已启动，监听端口 http://127.0.0.1%s\n", ListenPort)
	if err := http.ListenAndServe(ListenPort, mux); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("auth_token")
		if err != nil || cookie.Value == "" || cookie.Value != currToken {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "未登录或登录失效", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(loginHtml))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	user := r.FormValue("username")
	pass := r.FormValue("password")

	cfgLock.RLock()
	valid := (user == appConfig.Username && pass == appConfig.Password)
	cfgLock.RUnlock()

	if !valid {
		http.Error(w, "账号或密码错误", http.StatusUnauthorized)
		return
	}

	b := make([]byte, 16)
	rand.Read(b)
	hash := sha256.Sum256(append(b, []byte(time.Now().String())...))
	currToken = hex.EncodeToString(hash[:])

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    currToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 30, // 30 天免登录
	})

	w.WriteHeader(http.StatusOK)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "auth_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	oldPass := r.FormValue("old_password")
	newPass := strings.TrimSpace(r.FormValue("new_password"))

	if newPass == "" || len(newPass) < 6 {
		http.Error(w, "新密码长度不能少于 6 位", http.StatusBadRequest)
		return
	}

	cfgLock.Lock()
	defer cfgLock.Unlock()

	if oldPass != appConfig.Password {
		http.Error(w, "当前旧密码错误", http.StatusBadRequest)
		return
	}

	appConfig.Password = newPass
	if err := saveConfig(appConfig); err != nil {
		http.Error(w, "写入配置文件失败", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("密码修改成功"))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(htmlContent))
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxFileSize)
	if err := r.ParseMultipartForm(MaxFileSize); err != nil {
		http.Error(w, "文件大小超出限制 (单张≤10MB)", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "获取上传文件失败", http.StatusBadRequest)
		return
	}
	defer file.Close()

	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		http.Error(w, "读取文件失败", http.StatusInternalServerError)
		return
	}
	file.Seek(0, 0)

	mimeType := http.DetectContentType(buffer[:n])
	var ext string
	switch mimeType {
	case "image/jpeg":
		ext = ".jpg"
	case "image/png":
		ext = ".png"
	case "image/gif":
		ext = ".gif"
	case "image/webp":
		ext = ".webp"
	default:
		http.Error(w, "非法格式：仅支持 JPG, PNG, GIF, WEBP", http.StatusBadRequest)
		return
	}

	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	newFileName := hex.EncodeToString(randomBytes) + ext
	savePath := filepath.Join(UploadDir, newFileName)

	outFile, err := os.OpenFile(savePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		http.Error(w, "保存文件失败", http.StatusInternalServerError)
		return
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, file); err != nil {
		http.Error(w, "写入文件失败", http.StatusInternalServerError)
		return
	}

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	fileURL := fmt.Sprintf("%s://%s/i/%s", scheme, r.Host, newFileName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"url":  fileURL,
		"name": newFileName,
	})
}

func handleList(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(UploadDir)
	if err != nil {
		http.Error(w, "读取列表失败", http.StatusInternalServerError)
		return
	}

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}

	var list []ImageInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		list = append(list, ImageInfo{
			Name: entry.Name(),
			URL:  fmt.Sprintf("%s://%s/i/%s", scheme, r.Host, entry.Name()),
			Time: info.ModTime().Format("2006-01-02 15:04:05"),
			Size: info.Size(),
		})
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].Time > list[j].Time
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	filename := filepath.Base(r.URL.Query().Get("name"))
	if filename == "" || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		http.Error(w, "非法参数", http.StatusBadRequest)
		return
	}
	targetPath := filepath.Join(UploadDir, filename)
	if err := os.Remove(targetPath); err != nil {
		http.Error(w, "删除失败", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

const loginHtml = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录 - 私有图床</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f6f8; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
  .login-card { background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); width: 100%; max-width: 320px; }
  h2 { margin: 0 0 20px; font-size: 20px; text-align: center; color: #333; }
  .form-group { margin-bottom: 15px; }
  label { display: block; margin-bottom: 5px; font-size: 13px; color: #666; }
  input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; font-size: 14px; }
  button { width: 100%; padding: 10px; background: #0066cc; color: #fff; border: none; border-radius: 4px; font-size: 15px; cursor: pointer; }
  button:hover { background: #0052a3; }
</style>
</head>
<body>
<div class="login-card">
  <h2>私有图床登录</h2>
  <div class="form-group">
    <label>账号</label>
    <input type="text" id="username" autocomplete="off">
  </div>
  <div class="form-group">
    <label>密码</label>
    <input type="password" id="password">
  </div>
  <button onclick="doLogin()">登 录</button>
</div>
<script>
function doLogin() {
  const fd = new FormData();
  fd.append('username', document.getElementById('username').value);
  fd.append('password', document.getElementById('password').value);
  fetch('/api/login', { method: 'POST', body: fd })
    .then(r => {
      if (r.ok) { window.location.href = '/'; }
      else { alert('账号或密码错误'); }
    });
}
document.addEventListener('keydown', (e) => { if (e.key === 'Enter') doLogin(); });
</script>
</body>
</html>`

const htmlContent = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>极简自建图床</title>
<style>
  :root { --bg: #f5f6f8; --card: #ffffff; --text: #222; --primary: #0066cc; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; }
  .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
  .header-actions { display: flex; gap: 8px; }
  .container { max-width: 960px; margin: 0 auto; }
  .upload-box { background: var(--card); border: 2px dashed #ccd0d5; border-radius: 8px; padding: 40px 20px; text-align: center; cursor: pointer; transition: all .2s; }
  .upload-box:hover { border-color: var(--primary); }
  .upload-box.dragover { border-color: var(--primary); background: #f0f7ff; }
  .upload-box h3 { margin: 0 0 10px; color: #333; }
  .upload-box p { margin: 6px 0; color: #666; font-size: 14px; }
  .btn-paste { display: inline-block; margin-top: 10px; padding: 8px 16px; background: #e8f0fe; color: var(--primary); border: 1px solid #d2e3fc; border-radius: 4px; font-size: 13px; font-weight: 500; }
  .result-box { display: none; margin-top: 20px; background: var(--card); padding: 15px; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
  .copy-row { display: flex; gap: 8px; margin-bottom: 8px; align-items: center; }
  .copy-row label { width: 80px; font-size: 13px; font-weight: 600; color: #555; }
  .copy-row input { flex: 1; padding: 6px 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 13px; }
  .btn-copy { padding: 6px 12px; background: var(--primary); color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; }
  .history-title { margin: 40px 0 15px; font-size: 18px; font-weight: bold; border-left: 4px solid var(--primary); padding-left: 10px; }
  .gallery { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 16px; }
  .card { background: var(--card); border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.05); display: flex; flex-direction: column; }
  .card img { width: 100%; height: 140px; object-fit: cover; background: #eee; }
  .card-body { padding: 10px; font-size: 12px; color: #666; flex: 1; display: flex; flex-direction: column; justify-content: space-between; }
  .card-actions { display: flex; justify-content: space-between; margin-top: 8px; }
  .btn-action { color: var(--primary); text-decoration: none; cursor: pointer; border: none; background: none; font-size: 12px; padding: 0; }
  .btn-del { color: #d93025; }
  .btn-tool { background: none; border: 1px solid #ccc; padding: 5px 12px; border-radius: 4px; cursor: pointer; font-size: 13px; color: #555; }
  .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.4); justify-content: center; align-items: center; }
  .modal { background: #fff; padding: 25px; border-radius: 8px; width: 300px; box-shadow: 0 4px 15px rgba(0,0,0,0.15); }
  .modal h3 { margin: 0 0 15px; font-size: 16px; }
  .modal input { width: 100%; padding: 8px; margin-bottom: 12px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
  .modal-actions { display: flex; justify-content: flex-end; gap: 8px; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h2 style="margin:0; font-size: 20px;">我的私有图床</h2>
    <div class="header-actions">
      <button class="btn-tool" onclick="showPwdModal()">修改密码</button>
      <button class="btn-tool" onclick="location.href='/api/logout'">退出登录</button>
    </div>
  </div>

  <div class="upload-box" id="dropArea">
    <input type="file" id="fileInput" accept="image/png,image/jpeg,image/gif,image/webp" style="display:none">
    <h3>点击、拖拽 或 截图后直接 Ctrl+V 粘贴上传</h3>
    <p>支持 <code>Win + Shift + S</code> 截图后直接粘贴</p>
    <div class="btn-paste" id="btnClipboardPaste">📋 点击读取剪贴板并上传</div>
  </div>

  <div class="result-box" id="resultBox">
    <div class="copy-row">
      <label>URL 直链:</label>
      <input type="text" id="resUrl" readonly>
      <button class="btn-copy" onclick="copyVal('resUrl')">复制</button>
    </div>
    <div class="copy-row">
      <label>Markdown:</label>
      <input type="text" id="resMd" readonly>
      <button class="btn-copy" onclick="copyVal('resMd')">复制</button>
    </div>
  </div>

  <div class="history-title">过往上传</div>
  <div class="gallery" id="gallery"></div>
</div>

<div class="modal-overlay" id="pwdModal">
  <div class="modal">
    <h3>修改密码</h3>
    <input type="password" id="oldPwd" placeholder="请输入当前旧密码">
    <input type="password" id="newPwd" placeholder="请输入新密码（≥6位）">
    <div class="modal-actions">
      <button class="btn-tool" onclick="hidePwdModal()">取消</button>
      <button class="btn-tool" style="background:#0066cc;color:#fff;border-color:#0066cc;" onclick="submitNewPwd()">保存</button>
    </div>
  </div>
</div>

<script>
const dropArea = document.getElementById('dropArea');
const fileInput = document.getElementById('fileInput');

dropArea.onclick = (e) => {
  if (e.target.id === 'btnClipboardPaste') return;
  fileInput.click();
};
fileInput.onchange = (e) => {
  if (e.target.files.length) upload(e.target.files[0]);
};

['dragenter', 'dragover'].forEach(name => {
  dropArea.addEventListener(name, (e) => { e.preventDefault(); dropArea.classList.add('dragover'); });
});
['dragleave', 'drop'].forEach(name => {
  dropArea.addEventListener(name, (e) => { e.preventDefault(); dropArea.classList.remove('dragover'); });
});
dropArea.addEventListener('drop', (e) => {
  if (e.dataTransfer.files.length) upload(e.dataTransfer.files[0]);
});

window.addEventListener('paste', (e) => {
  const items = (e.clipboardData || window.clipboardData).items;
  for (let i = 0; i < items.length; i++) {
    if (items[i].type.indexOf('image') !== -1) {
      upload(items[i].getAsFile());
      break;
    }
  }
});

document.getElementById('btnClipboardPaste').onclick = async (e) => {
  e.stopPropagation();
  try {
    const items = await navigator.clipboard.read();
    for (const item of items) {
      for (const type of item.types) {
        if (type.startsWith('image/')) {
          const blob = await item.getType(type);
          upload(blob);
          return;
        }
      }
    }
    alert('剪贴板中没有找到图片');
  } catch (err) {
    alert('请直接在页面按 Ctrl + V 粘贴！');
  }
};

function upload(file) {
  if (!file) return;
  const formData = new FormData();
  formData.append('file', file, file.name || 'screenshot.png');

  fetch('/api/upload', { method: 'POST', body: formData })
    .then(r => {
      if (r.status === 401) { window.location.href = '/login'; return; }
      if (!r.ok) return r.text().then(t => { throw new Error(t); });
      return r.json();
    })
    .then(data => {
      if (!data) return;
      document.getElementById('resultBox').style.display = 'block';
      document.getElementById('resUrl').value = data.url;
      document.getElementById('resMd').value = ` + "`![](${data.url})`" + `;
      navigator.clipboard.writeText(` + "`![](${data.url})`" + `);
      loadHistory();
    })
    .catch(err => alert('上传失败: ' + err.message));
}

function loadHistory() {
  fetch('/api/list')
    .then(r => {
      if (r.status === 401) { window.location.href = '/login'; return; }
      return r.json();
    })
    .then(list => {
      if (!list) return;
      const g = document.getElementById('gallery');
      g.innerHTML = '';
      list.forEach(item => {
        const div = document.createElement('div');
        div.className = 'card';
        div.innerHTML = ` + "`" + `
          <a href="${item.url}" target="_blank"><img src="${item.url}" loading="lazy"></a>
          <div class="card-body">
            <div>${(item.size/1024).toFixed(1)} KB | ${item.time}</div>
            <div class="card-actions">
              <button class="btn-action" onclick="navigator.clipboard.writeText('${item.url}');alert('已复制直链');">复制链接</button>
              <button class="btn-action btn-del" onclick="delPic('${item.name}')">删除</button>
            </div>
          </div>` + "`" + `;
        g.appendChild(div);
      });
    });
}

function delPic(name) {
  if (!confirm('确认删除这张图片？')) return;
  fetch('/api/delete?name=' + encodeURIComponent(name), { method: 'POST' })
    .then(r => { if (r.ok) loadHistory(); else alert('删除失败'); });
}

function copyVal(id) {
  const el = document.getElementById(id);
  el.select();
  navigator.clipboard.writeText(el.value);
  alert('已复制到剪贴板');
}

function showPwdModal() {
  document.getElementById('pwdModal').style.display = 'flex';
  document.getElementById('oldPwd').value = '';
  document.getElementById('newPwd').value = '';
}
function hidePwdModal() {
  document.getElementById('pwdModal').style.display = 'none';
}
function submitNewPwd() {
  const oldPwd = document.getElementById('oldPwd').value;
  const newPwd = document.getElementById('newPwd').value;
  if (!oldPwd || !newPwd) { alert('请输入旧密码和新密码'); return; }

  const fd = new FormData();
  fd.append('old_password', oldPwd);
  fd.append('new_password', newPwd);

  fetch('/api/change-password', { method: 'POST', body: fd })
    .then(r => {
      if (r.ok) {
        alert('密码修改成功！下次登录请使用新密码。');
        hidePwdModal();
      } else {
        r.text().then(t => alert(t));
      }
    });
}

loadHistory();
</script>
</body>
</html>`
