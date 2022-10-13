package main

import (
	"database/sql"

	"encoding/json"

	"fmt"

	"io/ioutil"

	"net/http"

	_ "github.com/go-sql-driver/mysql"

	"golang.org/x/oauth2"

	"golang.org/x/oauth2/google"
)

type userInfoType struct {
	Id string `json:"id"`

	Email string `json:"email"`

	Picture string `json:"picture"`

	VerifiedEmail bool `json:"verified_email"`
}

type userInfoDBType struct {
	Id string `json:"id"`

	Email string `json:"email"`

	GoogleId string `json:"google_id"`

	GoogleToken string `json:"google_token"`
}

var (
	googleOauthConfig *oauth2.Config

	db *sql.DB

	// TODO: randomize it

	oauthStateString = "pseudo-random"
)

func init() {

	googleOauthConfig = &oauth2.Config{

		RedirectURL: "http://localhost:8080/callback",

		ClientID: "1075752496322-82nv2s6b4oqk3glail8phr94naqp301b.apps.googleusercontent.com",

		ClientSecret: "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",

		Scopes: []string{"https://www.googleapis.com/auth/userinfo.email"},

		Endpoint: google.Endpoint,
	}

	var err error

	db, err = sql.Open("mysql", "root:password@tcp(127.0.0.1:3306)/refactory")

	if err != nil {

		fmt.Errorf("can't connect mysql %s", err.Error())

	}

}

func main() {

	http.HandleFunc("/login", handleGoogleLogin)

	http.HandleFunc("/callback", handleGoogleCallback)

	http.HandleFunc("/user-info", handleGoogleUserInfo)

	fmt.Println(http.ListenAndServe(":8080", nil))

}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {

	url := googleOauthConfig.AuthCodeURL(oauthStateString)

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)

}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {

	email, token, err := saveUserData(r.FormValue("state"), r.FormValue("code"))

	if err != nil {

		fmt.Println(err.Error())

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)

		return

	}

	fmt.Fprintf(w, "User with email %s is successfully logged in with token %s", email, token)

}

func handleGoogleUserInfo(w http.ResponseWriter, r *http.Request) {

	userInfo, err := getUserInfo(r.FormValue("access_token"))

	if err != nil {

		fmt.Fprint(w, err.Error())

		return

	}

	responseData, err := json.Marshal(userInfo)

	if err != nil {

		fmt.Println(err.Error())

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)

		return

	}

	w.Header().Set("Content-Type", "application/json")

	w.Write(responseData)

}

func saveUserData(state string, code string) (string, string, error) {

	if state != oauthStateString {

		return "", "", fmt.Errorf("invalid oauth state")

	}

	token, err := googleOauthConfig.Exchange(oauth2.NoContext, code)

	if err != nil {

		return "", "", fmt.Errorf("code exchange failed: %s", err.Error())

	}

	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)

	if err != nil {

		return "", "", fmt.Errorf("failed getting user info: %s", err.Error())

	}

	defer response.Body.Close()

	var userInfo userInfoType

	var resultUser userInfoDBType

	data, _ := ioutil.ReadAll(response.Body)

	json.Unmarshal(data, &userInfo)

	err = db.QueryRow("SELECT email FROM users WHERE google_id=?", userInfo.Id).Scan(&resultUser.Email)

	if err != nil && err != sql.ErrNoRows {

		return "", "", fmt.Errorf("cannot query select", err.Error())

	}

	if resultUser.Email != "" {

		return resultUser.Email, token.AccessToken, nil

	}

	_, err = db.Exec("INSERT INTO users (email,google_id,google_token) VALUES (?,?,?)", userInfo.Email, userInfo.Id, token.AccessToken)

	if err != nil {

		return "", "", fmt.Errorf("failed insert", err.Error())

	}

	return userInfo.Email, token.AccessToken, nil

}

func getUserInfo(token string) (userInfoType, error) {

	var resultUser userInfoDBType

	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token)

	if err != nil {

		return userInfoType{}, fmt.Errorf("failed getting user info: %s", err.Error())

	} else if response.StatusCode != 200 {

		return userInfoType{}, fmt.Errorf("failed getting user info")

	}

	defer response.Body.Close()

	data, _ := ioutil.ReadAll(response.Body)

	var userInfo userInfoType

	json.Unmarshal(data, &userInfo)

	err = db.QueryRow("SELECT email FROM users WHERE google_id=?", userInfo.Id).Scan(&resultUser.Email)

	if err == sql.ErrNoRows {

		return userInfoType{}, fmt.Errorf("user is not registered")

	}

	if err != nil && err != sql.ErrNoRows {

		return userInfoType{}, fmt.Errorf("cannot query select", err.Error())

	}

	if err != nil {

		return userInfoType{}, fmt.Errorf("failed reading response body: %s", err.Error())

	}

	return userInfo, nil

}
