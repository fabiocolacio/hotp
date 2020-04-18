package hotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
)

// Truncate is the Truncation function for Hotp and Totp code generation defined in
// RFC 4226. Sum is the 20-byte HMAC-SHA1 output, and digits is the number of digits
// for the output code.
func Truncate(sum []byte, digits int) int {
	if len(sum) < 20 {
		panic("Hash must be 20 bytes")
	}

	offset := 0xf & sum[19]
	if p, n := binary.Uvarint(sum[offset:offset+4]); n == 0 {
		panic("Buffer too small!")
	} else if n < 0 {
		panic("Value is larger than 64 bits!")
	} else {
		p &= 0x7fffffff
		mod := 1

		for i := 0; i < digits; i++ {
			mod *= 10	
		}

		return int(p % uint64(mod))
	}
}

// Hotp calculates the hotp value for the given counter using the given key.
// The number of digits for the output code is provided by digits.
func Hotp(key []byte, counter int64, digits int) int {
	mac := hmac.New(sha1.New, key)
	binary.Write(mac, binary.LittleEndian, counter)
	tag := mac.Sum(nil)
	return Truncate(tag, digits)
}

// Totp calculates a Totp value using the key and number of digits supplied.
// Counter is the current Unix time, epoch is a relative epoch (can be 0).
// Duration is how long the code will remain valid (in seconds).
func Totp(key []byte, counter, epoch, duration int64, digits int) int {
	return Hotp(key, int64((counter - epoch) / duration), digits)
}

