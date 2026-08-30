package main

import (
	_ "github.com/scd-systems/authpf-api-extensions/v1/file-rbac"
	_ "github.com/scd-systems/authpf-api-extensions/v1/prometheus-metrics"
	_ "github.com/scd-systems/authpf-api-extensions/v1/rate-limit"
	"github.com/scd-systems/authpf-api/internal/server"
)

func main() {
	s := server.NewServer()
	s.Start()
}
