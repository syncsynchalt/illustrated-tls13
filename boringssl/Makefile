all: boringssl build/stamp link

boringssl:
	git clone git@github.com:google/boringssl.git
	cd boringssl && git checkout 74944287e1ab95e091107c9f26ce46bd50e13043
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
	rm -rf boringssl build include libssl.a libcrypto.a

.PHONY: all link clean
