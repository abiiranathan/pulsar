package main

import (
	"log"
	"net/http"
	"os"
	"strconv"

	pulsar "github.com/abiiranathan/pulsar/pulsar-go"
)

type EchoRequest struct {
	Message string `json:"message"`
	From    string `json:"from"`
}

type User struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func main() {
	app := pulsar.New()

	// Install panic recovery middleware
	app.Use(pulsar.Recover())

	// Global header middleware
	app.Use(func(c *pulsar.Context) error {
		c.SetHeader("X-Powered-By", "Pulsar-Go")
		return c.Next()
	})

	// Root endpoint
	app.Get("/", func(c *pulsar.Context) error {
		return c.String(http.StatusOK, "Welcome to Pulsar Go!")
	})

	// JSON response handler returning clean error
	app.Get("/user/{id}", func(c *pulsar.Context) error {
		id := c.Param("id")
		if id == "0" {
			return pulsar.NewHTTPError(http.StatusNotFound, "User not found")
		}
		return c.JSON(http.StatusOK, User{
			ID:   id,
			Name: "Pulsar User",
		})
	})

	// Group routing: /api/v1
	v1 := app.Group("/api/v1")
	{
		// Scoped auth middleware
		requireAuth := func(c *pulsar.Context) error {
			if c.Header("Authorization") == "" {
				c.Abort()
				return pulsar.NewHTTPError(http.StatusUnauthorized, "Missing Authorization header")
			}
			return c.Next()
		}

		v1.Post("/echo", func(c *pulsar.Context) error {
			var req EchoRequest
			if err := c.BindJSON(&req); err != nil {
				return err // Returns 400 with JSON error details automatically
			}
			return c.JSON(http.StatusOK, req)
		}, requireAuth)
	}

	// URL-encoded form echo: name=john+doe&city=...
	app.Post("/form", func(c *pulsar.Context) error {
		return c.JSON(http.StatusOK, map[string]any{
			"name": c.PostFormValue("name"),
			"all":  c.PostForm(),
		})
	})

	// Multipart upload: file bytes are never copied by the parser —
	// UploadedFile.Data is a zero-copy view into the request body.
	app.Post("/upload", func(c *pulsar.Context) error {
		file, err := c.FormFile("file")
		if err != nil {
			return err // 400 when the field is missing or the body is malformed
		}
		return c.JSON(http.StatusOK, map[string]any{
			"filename": file.Filename,
			"mime":     file.MimeType,
			"size":     file.Size,
			"note":     c.FormValue("note"),
		})
	})

	port := 8080
	if v := os.Getenv("PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
			port = p
		}
	}

	log.Printf("Starting Pulsar server on http://0.0.0.0:%d", port)
	if err := app.Listen("0.0.0.0", port); err != nil {
		log.Fatalf("Server stopped: %v", err)
	}
}
