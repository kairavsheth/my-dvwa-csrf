package main

import (
	"database/sql"
	"github.com/labstack/echo/v4"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4/middleware"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, _ echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

type User struct {
	Username string
}

var store = sessions.NewCookieStore([]byte("super-secret-key"))

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	db := connectDB()
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	e := echo.New()
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"*"}, // Allow all origins
		AllowMethods:     []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete},
		AllowHeaders:     []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept},
		AllowCredentials: true, // Allow sending cookies
	}))

	e.Renderer = &Template{
		templates: template.Must(template.ParseGlob("views/*.html")),
	}

	e.Use(middleware.Logger())
	e.Use(sessionMiddleware)

	e.GET("/", indexHandler)
	e.GET("/register", registerFormHandler)
	e.POST("/register", registerHandler)
	e.GET("/login", loginFormHandler)
	e.POST("/login", loginHandler)
	e.POST("/logout", logoutHandler)
	e.GET("/change-password", changePasswordFormHandler)
	e.POST("/change-password", changePasswordHandler)
	e.GET("/claim-gift", exploitHandler)

	e.Logger.Fatal(e.Start(":8080"))
}

func connectDB() *sql.DB {
	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	return db
}

func sessionMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		session, _ := store.Get(c.Request(), "session")
		if username, ok := session.Values["username"].(string); ok {
			c.Set("user", &User{Username: username})
		}
		return next(c)
	}
}

// Handlers
func indexHandler(c echo.Context) error {
	user, ok := c.Get("user").(*User)
	if !ok {
		return c.Redirect(http.StatusSeeOther, "/login")
	}
	return c.Render(http.StatusOK, "index.html", user)
}

func exploitHandler(c echo.Context) error {
	return c.Render(http.StatusOK, "exploit.html", nil)
}

func registerFormHandler(c echo.Context) error {
	return c.Render(http.StatusOK, "register.html", nil)
}

func registerHandler(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = connectDB().Exec(
		"INSERT INTO users (username, password_hash) VALUES ($1, $2)",
		username, hashedPassword,
	)
	if err != nil {
		//return c.String(http.StatusBadRequest, "Username already exists")
		return c.String(http.StatusBadRequest, err.Error())
	}

	return c.Redirect(http.StatusSeeOther, "/login")
}

func loginFormHandler(c echo.Context) error {
	return c.Render(http.StatusOK, "login.html", nil)
}

func loginHandler(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	var storedHash string
	err := connectDB().QueryRow(
		"SELECT password_hash FROM users WHERE username = $1", username,
	).Scan(&storedHash)
	if err != nil {
		return c.String(http.StatusUnauthorized, "Invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password)); err != nil {
		return c.String(http.StatusUnauthorized, "Invalid credentials")
	}

	session, _ := store.Get(c.Request(), "session")
	session.Values["username"] = username
	err = session.Save(c.Request(), c.Response())
	if err != nil {
		return err
	}

	return c.Redirect(http.StatusSeeOther, "/")
}

func logoutHandler(c echo.Context) error {
	session, _ := store.Get(c.Request(), "session")
	delete(session.Values, "username")
	err := session.Save(c.Request(), c.Response())
	if err != nil {
		return err
	}
	return c.Redirect(http.StatusSeeOther, "/login")
}

func changePasswordFormHandler(c echo.Context) error {
	return c.Render(http.StatusOK, "change_password.html", nil)
}

func changePasswordHandler(c echo.Context) error {
	user := c.Get("user").(*User)
	newPassword := c.FormValue("new_password")
	confirmPassword := c.FormValue("confirm_password")

	if newPassword != confirmPassword {
		return c.String(http.StatusBadRequest, "Passwords do not match")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = connectDB().Exec(
		"UPDATE users SET password_hash = $1 WHERE username = $2",
		hashedPassword, user.Username,
	)
	if err != nil {
		return err
	}

	return c.Redirect(http.StatusSeeOther, "/")
}
