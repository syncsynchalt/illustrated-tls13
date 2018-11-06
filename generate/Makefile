all: site

generator:
	go get github.com/syncsynchalt/illustrated-tls/cmd/generator
	cp ~/go/bin/generator .

hkdf:
	git clone git@github.com:syncsynchalt/hkdf

site: generator hkdf
	./generator < index.html.template > ../site/index.html
	./generator < certificate.html.template > ../site/certificate.html
	mkdir -p ../site/files/
	cp -a ../tools/aes_128_gcm_decrypt.c ../site/files/
	cp -a ../tools/aes_128_gcm_encrypt.c ../site/files/
	cp -a ../server/server.key ../server/server.crt ../site/files/
	cp -a hkdf/hkdf ../site/files/hkdf.sh

clean:
	rm -f generator
