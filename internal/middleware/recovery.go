package middleware

import (
	"log"
	"net/http"
	"runtime/debug"
	"time"
)

func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("PANIC [%s %s]: %v\n%s", r.Method, r.URL.Path, err, debug.Stack())
				http.Error(w, "Server error", http.StatusInternalServerError)
			}
		}()

		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[%s] %s | Duration: %v", r.Method, r.URL.Path, time.Since(start))
	})
}