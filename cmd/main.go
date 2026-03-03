package main

import (
	"github.com/scd-systems/authpf-api/internal/server"
)

func main() {
	s := server.NewServer()
	s.Start()
}
