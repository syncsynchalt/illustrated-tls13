all: boringssl build/stamp link

boringssl:
	git clone git@github.com:google/boringssl.git
	cd boringssl && git checkout 144d924e0b3c3a5ceb7083a408ba69b7cca1a25c
	cd boringssl && patch -p1 < ../tls13.patch
	cd boringssl && patch -p1 < ../instruments.patch

build/stamp:
	rm -rf build
	mkdir build
	cd build && cmake -DCMAKE_BUILD_TYPE=Release ../boringssl
	cd build && make
	touch build/stamp

link: build/stamp
	ln -sf ./build/ssl/libssl.a ./libssl.a
	ln -sf ./build/crypto/libcrypto.a ./libcrypto.a
	ln -sf ./boringssl/include ./include

clean:
	rm -rf boringssl build

.PHONY: all link clean
