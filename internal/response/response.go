package response

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func Json(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

func Error(w http.ResponseWriter, status int, message string, code string, err error) {
	if status >= 500 && err != nil {
		slog.Error("HTTP request failed",
			"status", status,
			"user_message", message,
			"code", code,
			"internal_error", err.Error(),
		)
	}
	Json(w, status, map[string]string{"error": message, "code": code})
}
