package main

import "net/http"
import "encoding/json"

type User struct{
	ID string `json:"id"`
	Name string `json:"name"`
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		u := User{
			ID: "1",
			Name: "Abiira Nathan",
		}

		json.NewEncoder(w).Encode(u)
	})

	http.ListenAndServe(":8080", nil)
}
