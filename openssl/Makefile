all: link

openssl/checkout.stamp:
	git clone --depth 1 --branch openssl-3.0.1 git://git.openssl.org/openssl.git
	cd openssl && patch -p1 < ../instruments.patch
	touch openssl/checkout.stamp

openssl/build.stamp: openssl/checkout.stamp
	cd openssl && ./config -d no-asm
	cd openssl && make
	touch openssl/build.stamp

link: openssl/build.stamp
	rm -rf include libssl.a libcrypto.a
	ln -sf ./openssl/libssl.a ./libssl.a
	ln -sf ./openssl/libcrypto.a ./libcrypto.a
	ln -sf ./openssl/include ./include

clean:
	rm -rf openssl include libssl.a libcrypto.a

.PHONY: all link clean
