package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Password string   `json:"password"`
	Files    []string `json:"files"`
}

var config Config
var store = sessions.NewCookieStore([]byte("secret-key"))

func main() {
	loadConfig()

	r := mux.NewRouter()
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/admin", adminHandler)
	r.HandleFunc("/login", loginHandler)
	r.HandleFunc("/logout", logoutHandler)
	r.HandleFunc("/upload", uploadHandler)
	r.HandleFunc("/delete-file", deleteFileHandler)
	r.HandleFunc("/change-password", changePasswordHandler)
	r.HandleFunc("/download/{filename}", downloadHandler)

	fs := http.FileServer(http.Dir("./static"))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))

	// Lancer le serveur dans une goroutine
	go func() {
		fmt.Println("Server running on http://localhost:8080")
		log.Fatal(http.ListenAndServe(":8080", r))
	}()

	// Ouvrir le navigateur
	openBrowser("http://localhost:8080")

	// Attendre indéfiniment
	select {}
}

func openBrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}

	if err != nil {
		log.Printf("Error opening browser: %v", err)
	}
}

func loadConfig() {
	file, err := os.ReadFile("config.json")
	if err != nil {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		config = Config{Password: string(hashedPassword), Files: []string{}}
		saveConfig()
	} else {
		json.Unmarshal(file, &config)
	}
}

func saveConfig() {
	file, _ := json.MarshalIndent(config, "", " ")
	os.WriteFile("config.json", file, 0644)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/home.html"))
	tmpl.Execute(w, config)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tmpl := template.Must(template.ParseFiles("templates/admin.html"))
	tmpl.Execute(w, config)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	password := r.FormValue("password")
	err := bcrypt.CompareHashAndPassword([]byte(config.Password), []byte(password))
	if err == nil {
		session, _ := store.Get(r, "session")
		session.Values["authenticated"] = true
		session.Save(r, w)
		fmt.Fprintf(w, "success")
	} else {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	session.Values["authenticated"] = false
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := header.Filename
	f, err := os.OpenFile("./uploads/"+filename, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	io.Copy(f, file)

	config.Files = append(config.Files, filename)
	saveConfig()

	fmt.Fprintf(w, "File uploaded successfully")
}

func deleteFileHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := r.FormValue("filename")
	err := os.Remove("./uploads/" + filename)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for i, f := range config.Files {
		if f == filename {
			config.Files = append(config.Files[:i], config.Files[i+1:]...)
			break
		}
	}
	saveConfig()

	fmt.Fprintf(w, "File deleted successfully")
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	newPassword := r.FormValue("new_password")
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	config.Password = string(hashedPassword)
	saveConfig()

	fmt.Fprintf(w, "Password changed successfully")
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	filename := vars["filename"]

	filepath := filepath.Join("uploads", filename)
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	http.ServeFile(w, r, filepath)
}
