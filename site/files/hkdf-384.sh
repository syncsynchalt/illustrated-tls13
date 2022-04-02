#!/bin/bash

# Perform HKDF with SHA384 hashing - such as might be used for TLS_AES_256_GCM_SHA384

op=$1
if [[ "$op" = "extract" ]]; then
	hexsalt="$2" hexkeymaterial="$3"

	if [[ "$hexsalt" = "" ]]; then
		hexsalt="000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	fi
	echo -en "$hexkeymaterial" | xxd -r -p | openssl dgst -sha384 -mac HMAC -macopt hexkey:"$hexsalt" -hex \
		| sed -e 's/.* //'
elif [[ "$op" = "expand" || "$op" = "expandlabel" ]]; then
	if [[ "$op" = "expand" ]]; then
		hexprk="$2" hexinfo="$3" length="$4"
	elif [[ "$op" = "expandlabel" ]]; then
		hexprk="$2" label="$3" hexcontext="$4" length="$5"
		labellen=$(echo -n "$label" | wc -c | awk '{print $1}')
		let labellen=labellen+6
		contextlen=$(echo -n "$hexcontext" | wc -c | awk '{print $1}')
		let contextlen=contextlen/2
		hexinfo=$(printf "%04x" "$length" )$(printf "%02x" "$labellen")
		hexinfo=${hexinfo}$(echo -en "tls13 $label" | xxd -p )
		hexinfo=${hexinfo}$(printf "%02x" "$contextlen")"$hexcontext"
	fi

	let hexlength="$length"*2
	hexoutput=
	hexlast=
	i=1
	while [[ $(echo -n "$hexoutput" | wc -c) -lt $hexlength ]]; do
		hexin=${hexlast}${hexinfo}$(printf "%02x" "$i")
		hexlast=$(echo -en "$hexin" | xxd -r -p | openssl dgst -sha384 -mac HMAC -macopt hexkey:"$hexprk" -hex \
			| sed -e 's/.* //')
		hexoutput=${hexoutput}${hexlast}
		let i++
	done
	echo -n "$hexoutput" | head -c "$hexlength"
	echo
else
	cat <<EOF >&2
Usage:

  $0 extract hexsalt hexkey
    - perform the HKDF-Extract function to concentrate key material
  $0 expand hexprk hexinfo length
    - perform the HKDF-Expand function to generate keys
  $0 expandlabel hexprk label hexcontext length
    - perform the HKDF-Expand-Label function as defined in RFC 8446 (TLS 1.3)

EOF
fi
