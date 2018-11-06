all: site

generator:
	go get github.com/syncsynchalt/illustrated-tls/cmd/generator
	cp ~/go/bin/generator .

site: generator
	./generator < index.html.template > ../site/index.html
	./generator < certificate.html.template > ../site/certificate.html
	mkdir -p ../site/files/
	cp -a ../tools/aes_128_gcm_decrypt.c ../site/files/
	cp -a ../tools/aes_128_gcm_encrypt.c ../site/files/
	cp -a ../server/server.key ../server/server.crt ../site/files/

clean:
	rm -f generator
