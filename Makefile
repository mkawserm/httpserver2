VERSION = "0.0.1"
change-version:
	@echo $(VERSION)>VERSION

run:
	go run main/main.go embedded run

build:
	go build -o bin/httpserver2 main/main.go

update-module:
	go env -w GOPRIVATE=github.com/mkawserm
	go get -v github.com/mkawserm/abesh
	go get -v github.com/julienschmidt/httprouter

