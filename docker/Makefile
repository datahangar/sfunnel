all: build

build:
	docker build --progress=plain -f ./Dockerfile -t sfunnel --build-arg VERSION="`git describe`" --build-arg COMMIT="`git rev-parse HEAD`" ../
