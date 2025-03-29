all:
	go build ./cmd/vhost
	go build ./cmd/vrouter

clean:
	rm -fv vhost
	rm -fv vrouter