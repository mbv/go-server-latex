export GOROOT=/usr/local/go
export GOPATH=/var/work/go_libs
export PATH=$PATH:$GOROOT/bin

PORT=80 go run server.go