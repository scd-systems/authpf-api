package server

import (
	"encoding/json"
	"fmt"

	"github.com/scd-systems/authpf-api/internal/api"
)

type VersionInfo struct {
	ServerVersion string `json:"server_version"`
	APIVersion    string `json:"api_version"`
}

func GetVersionInfo() VersionInfo {
	return VersionInfo{
		ServerVersion: Version,
		APIVersion:    api.API_VERSION,
	}
}

func displayVersionInfo() {
	info := GetVersionInfo()
	jsonData, _ := json.MarshalIndent(info, "", "  ")
	fmt.Println(string(jsonData))
}
