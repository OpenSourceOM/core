// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed web/*
var webAssets embed.FS

func uiHandler() http.Handler {
	sub, err := fs.Sub(webAssets, "web")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}
