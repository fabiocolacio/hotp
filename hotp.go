package hotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
)

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

func Hotp(key []byte, counter int64, digits int) int {
	mac := hmac.New(sha1.New, key)
	binary.Write(mac, binary.LittleEndian, counter)
	tag := mac.Sum(nil)
	return Truncate(tag, digits)
}

func Totp(key []byte, counter, epoch, duration int64, digits int) int {
	return Hotp(key, (counter - epoch) / duration, digits)
}

