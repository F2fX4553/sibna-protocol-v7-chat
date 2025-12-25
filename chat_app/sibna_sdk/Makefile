.PHONY: build clean test install

build:
	cd core && cargo build --release

clean:
	cd core && cargo clean
	rm -rf build dist *.egg-info

test:
	cd core && cargo test

install: build
	pip install -e .

all: build install
