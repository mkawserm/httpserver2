package main

import _ "embed"

import "github.com/mkawserm/abesh/cmd"
import _ "github.com/mkawserm/httpserver2/capability/httpserver2"
import _ "github.com/mkawserm/abesh/example/echo"

//go:embed manifest.yaml
var manifestBytes []byte

func main() {
	cmd.ManifestBytes = manifestBytes
	cmd.Execute()
}
