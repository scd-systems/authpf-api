package server

import (
	"sync"
)

// Global variables
var (
	Version   = "dev"
	lock      = &sync.Mutex{}
	jwtSecret = []byte{}
)

var (
	ROUTE_AUTHPF     = "/api/v1/authpf/activate"
	ROUTE_AUTHPF_ALL = "/api/v1/authpf/all"
	ROUTE_LOGIN      = "/login"
)
