TARGETS=clientdataplain clientfinishedplain serverdataplain serverhandshake serverticketsplain
all: targets
targets: aes_128_gcm_decrypt
	$(MAKE) $(TARGETS)

aes_128_gcm_decrypt.c:
	curl -sO https://tls13.ulfheim.net/files/aes_128_gcm_decrypt.c

aes_128_gcm_decrypt: aes_128_gcm_decrypt.c
	cc -I ../../boringssl/boringssl/include \
		-o aes_128_gcm_decrypt aes_128_gcm_decrypt.c \
		-L ../../boringssl -lssl -lcrypto

clientdataplain: clientdata
	$(eval KEY = 49134b95328f279f0183860589ac6707)
	$(eval IV = bc4dd5f7b98acff85466261d)
	$(eval RECDATA = $(shell head -c 5 $^ | xxd -p))
	$(eval AUTHTAG = $(shell tail -c 16 $^ | xxd -p))
	$(eval RECORDNUM = 0)
	perl -p0777 -e 's/.{5}//s;s/.{16}$$//s' < $^ > /tmp/working
	cat /tmp/working | ./aes_128_gcm_decrypt $(IV) $(RECORDNUM) $(KEY) $(RECDATA) $(AUTHTAG) > $@

clientfinishedplain: clientfinished
	$(eval KEY = 7154f314e6be7dc008df2c832baa1d39)
	$(eval IV = 71abc2cae4c699d47c600268)
	$(eval RECDATA = $(shell head -c 5 $^ | xxd -p))
	$(eval AUTHTAG = $(shell tail -c 16 $^ | xxd -p))
	$(eval RECORDNUM = 0)
	perl -p0777 -e 's/.{5}//s;s/.{16}$$//s' < $^ > /tmp/working
	cat /tmp/working | ./aes_128_gcm_decrypt $(IV) $(RECORDNUM) $(KEY) $(RECDATA) $(AUTHTAG) > $@

serverdataplain: serverdata
	$(eval KEY = 0b6d22c8ff68097ea871c672073773bf)
	$(eval IV = 1b13dd9f8d8f17091d34b349)
	$(eval RECDATA = $(shell head -c 5 $^ | xxd -p))
	$(eval AUTHTAG = $(shell tail -c 16 $^ | xxd -p))
	$(eval RECORDNUM = 1)
	perl -p0777 -e 's/.{5}//s;s/.{16}$$//s' < $^ > /tmp/working
	cat /tmp/working | ./aes_128_gcm_decrypt $(IV) $(RECORDNUM) $(KEY) $(RECDATA) $(AUTHTAG) > $@

serverhandshake: serverenchandshake
	$(eval KEY = 844780a7acad9f980fa25c114e43402a)
	$(eval IV = 4c042ddc120a38d1417fc815)
	$(eval RECDATA = $(shell head -c 5 $^ | xxd -p))
	$(eval AUTHTAG = $(shell tail -c 16 $^ | xxd -p))
	$(eval RECORDNUM = 0)
	perl -p0777 -e 's/.{5}//s;s/.{16}$$//s' < $^ > /tmp/working
	cat /tmp/working | ./aes_128_gcm_decrypt $(IV) $(RECORDNUM) $(KEY) $(RECDATA) $(AUTHTAG) > $@

serverticketsplain: servertickets
	$(eval KEY = 0b6d22c8ff68097ea871c672073773bf)
	$(eval IV = 1b13dd9f8d8f17091d34b349)
	$(eval RECDATA = $(shell head -c 5 $^ | xxd -p))
	$(eval AUTHTAG = $(shell tail -c 16 $^ | xxd -p))
	$(eval RECORDNUM = 0)
	perl -p0777 -e 's/.{5}//s;s/.{16}$$//s' < $^ > /tmp/working
	cat /tmp/working | ./aes_128_gcm_decrypt $(IV) $(RECORDNUM) $(KEY) $(RECDATA) $(AUTHTAG) > $@

clean:
	rm -f aes_128_gcm_decrypt aes_128_gcm_decrypt.c

reset:
	touch -t 0001010000 $(TARGETS)
