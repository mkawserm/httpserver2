VERSION = "0.0.1"
change-version:
	@echo $(VERSION)>VERSION
	@echo "package constant\n\n//Version constant of httpserver2\nconst Version = \"$(VERSION)\"">constant/version.go
	@git add VERSION
	@git add constant/version.go
	@git commit -m "v$(VERSION)"
	@git tag -a "v$(VERSION)" -m "v$(VERSION)"
	@git push origin
	@git push origin "v$(VERSION)"

run:
	go run main/main.go embedded run

run2:
	go run main/main.go embedded-run2

build:
	go build -o bin/httpserver2 main/main.go

update-module:
	go env -w GOPRIVATE=github.com/mkawserm
	go get -v github.com/mkawserm/abesh
	go get -v github.com/julienschmidt/httprouter

