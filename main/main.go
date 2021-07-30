package main

import "github.com/mkawserm/abesh/cmd"
import _ "github.com/mkawserm/httpserver2/capability/httpserver2"
import _ "github.com/mkawserm/abesh/example/echo"

func main() {
	cmd.Execute()
}
