// vulnapp.go - a deliberately vulnerable demo net/http service used ONLY to test
// VulnHunter's multi-language scanner coverage. DO NOT deploy this anywhere. It
// contains intentional security flaws for demonstration purposes only.
//
// Planted vulnerabilities (for scoring / demo reference):
//   1. Command injection via exec.Command                -> CWE-78
//   2. SQL Injection via string-concatenated query        -> CWE-89
//   3. World-writable file permissions (0777)              -> CWE-276

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

// pingHandler VULN 1: Command injection (CWE-78) - the user-controlled "host" query
// param is passed straight into a shell-interpreted command instead of being used as a
// discrete, validated argument.
func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		host = "127.0.0.1"
	}
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "ping failed", http.StatusInternalServerError)
		return
	}
	w.Write(output)
}

// userHandler VULN 2: SQL Injection (CWE-89) - the query is built with fmt.Sprintf
// string concatenation instead of a parameterized "?" placeholder.
func userHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT id, username, email FROM users WHERE id = %s", userID)
	row := db.QueryRow(query)

	var id, username, email string
	if err := row.Scan(&id, &username, &email); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, "%s,%s,%s", id, username, email)
}

// exportHandler VULN 3: World-writable file permissions (CWE-276) - the export file is
// created with mode 0777, letting any local user read or modify it.
func exportHandler(w http.ResponseWriter, r *http.Request) {
	data := []byte("id,username,email\n")
	err := os.WriteFile("/tmp/vulnapp-export.csv", data, 0777)
	if err != nil {
		http.Error(w, "export failed", http.StatusInternalServerError)
		return
	}
	w.Write([]byte("exported"))
}

func main() {
	var err error
	db, err = sql.Open("sqlite3", "vulnshop.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/user", userHandler)
	http.HandleFunc("/export", exportHandler)
	http.ListenAndServe(":8080", nil)
}
