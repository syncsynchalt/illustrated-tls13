#!/bin/bash

# Perform HKDF with SHA384 hashing - such as might be used for TLS_AES_256_GCM_SHA384

op=$1
if [[ "$op" = "extract" ]]; then

	### RFC 5869 section 2.2
	#
	# HKDF-Extract(salt, IKM) -> PRK
	#
	# Options:
	#    Hash     a hash function; HashLen denotes the length of the
	#             hash function output in octets
	#
	# Inputs:
	#    salt     optional salt value (a non-secret random value);
	#             if not provided, it is set to a string of HashLen zeros.
	#    IKM      input keying material
	#
	# Output:
	#    PRK      a pseudorandom key (of HashLen octets)
	#
	# The output PRK is calculated as follows:
	#
	#    PRK = HMAC-Hash(salt, IKM)

	hexsalt="$2" hexkeymaterial="$3"

	if [[ "$hexsalt" = "" ]]; then
		hexsalt="000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	fi
	echo -en "$hexkeymaterial" | xxd -r -p | openssl dgst -sha384 -mac HMAC -macopt hexkey:"$hexsalt" -hex \
		| sed -e 's/.* //'

elif [[ "$op" = "expand" || "$op" = "expandlabel" ]]; then

	if [[ "$op" = "expand" ]]; then

		### RFC 5869 section 2.3
		#
		# HKDF-Expand(PRK, info, L) -> OKM
		#
		# Options:
		#    Hash     a hash function; HashLen denotes the length of the
		#             hash function output in octets
		#
		# Inputs:
		#    PRK      a pseudorandom key of at least HashLen octets
		#             (usually, the output from the extract step)
		#    info     optional context and application specific information
		#             (can be a zero-length string)
		#    L        length of output keying material in octets
		#           (<= 255*HashLen)
		#
		# Output:
		#    OKM      output keying material (of L octets)
		#
		# The output OKM is calculated as follows:
		#    N = ceil(L/HashLen)
		#    T = T(1) | T(2) | T(3) | ... | T(N)
		#    OKM = first L octets of T
		#
		# where:
		#    T(0) = empty string (zero length)
		#    T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
		#    T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
		#    T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
		#    ...
		#    (where the constant concatenated to the end of each T(n) is a
		#    single octet.)

		hexprk="$2" hexinfo="$3" length="$4"

	elif [[ "$op" = "expandlabel" ]]; then

		### RFC 8446 section 7.1
		#
		# The key derivation process makes use of the HKDF-Extract and
		# HKDF-Expand functions as defined above, as well as the
		# functions defined below:
		#
		# HKDF-Expand-Label(Secret, Label, Context, Length) =
		#   HKDF-Expand(Secret, HkdfLabel, Length)
		#
		# Where HkdfLabel is specified as:
		#
		# struct {
		#   uint16 length = Length;
		#   opaque label<7..255> = "tls13 " + Label;
		# 	opaque context<0..255> = Context;
		# } HkdfLabel;
		#
		# implementor's note: the above definition references variable-length vectors,
		# which in this case are preceded by a single-byte of length info.

		hexprk="$2" label="$3" hexcontext="$4" length="$5"
		labellen=$(echo -n "$label" | wc -c | awk '{print $1}')
		let labellen=labellen+6
		contextlen=$(echo -n "$hexcontext" | wc -c | awk '{print $1}')
		let contextlen=contextlen/2
		hkdflabel=$(printf "%04x" "$length")$(printf "%02x" "$labellen")
		hkdflabel=${hkdflabel}$(echo -en "tls13 $label" | xxd -p )
		hkdflabel=${hkdflabel}$(printf "%02x" "$contextlen")"$hexcontext"
		hexinfo=${hkdflabel}
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
