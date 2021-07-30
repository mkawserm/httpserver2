VERSION = "0.0.1"

run:
	go run main/main.go run --manifest example/manifest.yaml

build:
	go build -o bin/httpserver2 main/main.go
