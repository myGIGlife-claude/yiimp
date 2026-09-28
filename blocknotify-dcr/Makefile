# Go >= 1.21 required, the dependencies are fetched by the go tool (go.mod)
OUTPUT=blocknotify-dcr

all:
	go build -trimpath -ldflags "-s -w" -o $(OUTPUT) .

install: all
	killall -9 $(OUTPUT) || echo ok
	mv $(OUTPUT) ../bin/$(OUTPUT)
	@echo "start it with: ../bin/$(OUTPUT) -stratum 127.0.0.1:3252 -coinid <id> -rpcuser <u> -rpcpass <p> [-rpccert rpc.cert | -notls] &"

clean:
	rm -f $(OUTPUT)
