all: boringssl build link

boringssl:
	git clone git@github.com:google/boringssl.git
	cd boringssl && git checkout 144d924e0b3c3a5ceb7083a408ba69b7cca1a25c
	cd boringssl && patch -p1 < ../tls13.patch

build:
	mkdir build
	cd build && cmake -DCMAKE_BUILD_TYPE=Release ../boringssl
	cd build && make

link: build
	ln -sf ./build/ssl/libssl.a ./libssl.a
	ln -sf ./build/crypto/libcrypto.a ./libcrypto.a
	ln -sf ./boringssl/include ./include

clean:
	rm -rf boringssl build

.PHONY: all link clean
