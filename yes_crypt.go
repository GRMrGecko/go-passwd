package passwd

import (
	"fmt"

	"github.com/openwall/yescrypt-go"
)

type YesCrypt struct {
	Passwd
}

// Make an MD5Crypt password instance.
func NewYesCryptPasswd() PasswdInterface {
	m := new(YesCrypt)
	m.Magic = YES_CRYPT_MAGIC
	m.SetSCryptParams(11, 31)
	m.SaltLength = 22
	// Set the interface to allow parents to call overriden functions.
	m.i = m
	return m
}

// Sets the SCrypt params using integers.
func (a *YesCrypt) SetSCryptParams(N, r int) (err error) {
	Nval, err := IToA64(N)
	if err != nil {
		return
	}
	rval, err := IToA64(r)
	if err != nil {
		return
	}
	a.Params = fmt.Sprintf("j%c%c", Nval, rval)
	return
}

// Decode SCrypt params.
func (a *YesCrypt) DecodeSCriptParams() (N, r int) {
	b64 := []byte(a.Params)
	if len(b64) != 3 {
		return
	}
	N = AToI64(b64[1])
	r = AToI64(b64[2])
	return
}

// Hash a password with salt using yes crypt standard.
func (a *YesCrypt) Hash(password []byte, salt []byte) (hash []byte, err error) {
	output := fmt.Sprintf("%s%s$%s", a.Magic, a.Params, salt)
	hash, err = yescrypt.Hash(password, []byte(output))
	return
}

// Override the passwd hash with salt function to hash with yes crypt.
func (a *YesCrypt) HashPasswordWithSalt(password []byte, salt []byte) (hash []byte, err error) {
	hash, err = a.Hash(password, salt)
	return
}
