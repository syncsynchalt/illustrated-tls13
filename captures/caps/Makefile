TARGETS=serverextensions servercert servercertverify serverfinished clientfinished clientdata serverticket1 serverticket2 serverdata
all: cleartargets targets
targets: aes_256_gcm_decrypt
	$(MAKE) $(TARGETS)

aes_256_gcm_decrypt.c:
	curl -sO https://tls13.ulfheim.net/files/aes_256_gcm_decrypt.c

aes_256_gcm_decrypt: aes_256_gcm_decrypt.c
	cc -I ../../openssl/openssl/include \
		-o aes_256_gcm_decrypt aes_256_gcm_decrypt.c \
		-L ../../openssl -lssl -lcrypto

S_HS_KEY=9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f
S_HS_IV=9563bc8b590f671f488d2da3
C_HS_KEY=1135b4826a9a70257e5a391ad93093dfd7c4214812f493b3e3daae1eb2b1ac69
C_HS_IV=4256d2e0e88babdd05eb2f27

S_AP_KEY=01f78623f17e3edcc09e944027ba3218d57c8e0db93cd3ac419309274700ac27
S_AP_IV=196a750b0c5049c0cc51a541
C_AP_KEY=de2f4c7672723a692319873e5c227606691a32d1c59d8b9f51dbb9352e9ca9cc
C_AP_IV=bb007956f474b25de902432f

cleartargets:
	rm -f $(TARGETS)

serverextensions: serverencextensions
	$(eval KEY = $(S_HS_KEY))
	$(eval IV = $(S_HS_IV))
	$(eval RECDATA = $(shell head -c 5 $^ | xxd -p))
	$(eval AUTHTAG = $(shell tail -c 16 $^ | xxd -p))
	$(eval RECORDNUM = 0)
	perl -p0777 -e 's/.{5}//s;s/.{16}$$//s' < $^ > /tmp/working
	cat /tmp/working | ./aes_256_gcm_decrypt $(IV) $(RECORDNUM) $(KEY) $(RECDATA) $(AUTHTAG) > $@

servercert: serverenccert
	$(eval KEY = $(S_HS_KEY))
	$(eval IV = $(S_HS_IV))
	$(eval RECDATA = $(shell head -c 5 $^ | xxd -p))
	$(eval AUTHTAG = $(shell tail -c 16 $^ | xxd -p))
	$(eval RECORDNUM = 1)
	perl -p0777 -e 's/.{5}//s;s/.{16}$$//s' < $^ > /tmp/working
	cat /tmp/working | ./aes_256_gcm_decrypt $(IV) $(RECORDNUM) $(KEY) $(RECDATA) $(AUTHTAG) > $@

servercertverify: serverenccertverify
	$(eval KEY = $(S_HS_KEY))
	$(eval IV = $(S_HS_IV))
	$(eval RECDATA = $(shell head -c 5 $^ | xxd -p))
	$(eval AUTHTAG = $(shell tail -c 16 $^ | xxd -p))
	$(eval RECORDNUM = 2)
	perl -p0777 -e 's/.{5}//s;s/.{16}$$//s' < $^ > /tmp/working
	cat /tmp/working | ./aes_256_gcm_decrypt $(IV) $(RECORDNUM) $(KEY) $(RECDATA) $(AUTHTAG) > $@

serverfinished: serverencfinished
	$(eval KEY = $(S_HS_KEY))
	$(eval IV = $(S_HS_IV))
	$(eval RECDATA = $(shell head -c 5 $^ | xxd -p))
	$(eval AUTHTAG = $(shell tail -c 16 $^ | xxd -p))
	$(eval RECORDNUM = 3)
	perl -p0777 -e 's/.{5}//s;s/.{16}$$//s' < $^ > /tmp/working
	cat /tmp/working | ./aes_256_gcm_decrypt $(IV) $(RECORDNUM) $(KEY) $(RECDATA) $(AUTHTAG) > $@

clientfinished: clientencfinished
	$(eval KEY = $(C_HS_KEY))
	$(eval IV = $(C_HS_IV))
	$(eval RECDATA = $(shell head -c 5 $^ | xxd -p))
	$(eval AUTHTAG = $(shell tail -c 16 $^ | xxd -p))
	$(eval RECORDNUM = 0)
	perl -p0777 -e 's/.{5}//s;s/.{16}$$//s' < $^ > /tmp/working
	cat /tmp/working | ./aes_256_gcm_decrypt $(IV) $(RECORDNUM) $(KEY) $(RECDATA) $(AUTHTAG) > $@

clientdata: clientencdata
	$(eval KEY = $(C_AP_KEY))
	$(eval IV = $(C_AP_IV))
	$(eval RECDATA = $(shell head -c 5 $^ | xxd -p))
	$(eval AUTHTAG = $(shell tail -c 16 $^ | xxd -p))
	$(eval RECORDNUM = 0)
	perl -p0777 -e 's/.{5}//s;s/.{16}$$//s' < $^ > /tmp/working
	cat /tmp/working | ./aes_256_gcm_decrypt $(IV) $(RECORDNUM) $(KEY) $(RECDATA) $(AUTHTAG) > $@

serverticket1: serverencticket1
	$(eval KEY = $(S_AP_KEY))
	$(eval IV = $(S_AP_IV))
	$(eval RECDATA = $(shell head -c 5 $^ | xxd -p))
	$(eval AUTHTAG = $(shell tail -c 16 $^ | xxd -p))
	$(eval RECORDNUM = 0)
	perl -p0777 -e 's/.{5}//s;s/.{16}$$//s' < $^ > /tmp/working
	cat /tmp/working | ./aes_256_gcm_decrypt $(IV) $(RECORDNUM) $(KEY) $(RECDATA) $(AUTHTAG) > $@

serverticket2: serverencticket2
	$(eval KEY = $(S_AP_KEY))
	$(eval IV = $(S_AP_IV))
	$(eval RECDATA = $(shell head -c 5 $^ | xxd -p))
	$(eval AUTHTAG = $(shell tail -c 16 $^ | xxd -p))
	$(eval RECORDNUM = 1)
	perl -p0777 -e 's/.{5}//s;s/.{16}$$//s' < $^ > /tmp/working
	cat /tmp/working | ./aes_256_gcm_decrypt $(IV) $(RECORDNUM) $(KEY) $(RECDATA) $(AUTHTAG) > $@

serverdata: serverencdata
	$(eval KEY = $(S_AP_KEY))
	$(eval IV = $(S_AP_IV))
	$(eval RECDATA = $(shell head -c 5 $^ | xxd -p))
	$(eval AUTHTAG = $(shell tail -c 16 $^ | xxd -p))
	$(eval RECORDNUM = 2)
	perl -p0777 -e 's/.{5}//s;s/.{16}$$//s' < $^ > /tmp/working
	cat /tmp/working | ./aes_256_gcm_decrypt $(IV) $(RECORDNUM) $(KEY) $(RECDATA) $(AUTHTAG) > $@

clean:
	rm -f aes_256_gcm_decrypt aes_256_gcm_decrypt.c
	rm -f $(TARGETS)
