all: mac linux win32
	@echo "compiled all."

mac:
	GOARCH=amd64 GOOS=darwin go build -o bin/caa-validator-darwin-amd64

linux:
	GOARCH=386 GOOS=linux go build -o bin/caa-validator-linux-386
	GOARCH=amd64 GOOS=linux go build -o bin/caa-validator-linux-amd64

win32:
	GOARCH=386 GOOS=windows go build -o bin/caa-validator-windows-386.exe
	GOARCH=amd64 GOOS=windows go build -o bin/caa-validator-windows-amd64.exe

