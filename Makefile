all:

dist:
	@if [[ -z "${DISTROOT}" ]]; then echo "Must set \$$DISTROOT variable"; exit 1; fi
	rsync -rlpvhc site/ ${DISTROOT}/tls13/
