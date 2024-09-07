package passwd

import (
	"fmt"
	"testing"
)

func TestPasswd(t *testing.T) {
	password := []byte("Test")
	var res bool
	var err error

	// Confirm password hashes conform to libcrypt standards.
	res, err = CheckPassword([]byte("$sha1$245081$NabW/sfk3ZVVQc4BnZ/3$YoV1Iva6GK4tkxwahBmyH0TRCwBO"), password)
	if err != nil {
		t.Fatalf("sha1 error: %s", err)
	}
	if !res {
		t.Fatalf("Password check for sha1 failed")
	}

	res, err = CheckPassword([]byte("$md5$lORrojKC$$RD9p64URLn3Wkv4Wa2xOW0"), password)
	if err != nil {
		t.Fatalf("sun md5 error: %s", err)
	}
	if !res {
		t.Fatalf("Password check for sun md5 failed")
	}

	res, err = CheckPassword([]byte("$md5,rounds=53125$qrDebYUd$$3pJWS.a6VTC/cGehIfQb30"), password)
	if err != nil {
		t.Fatalf("sun md5 with rounds error: %s", err)
	}
	if !res {
		t.Fatalf("Password check for sun md5 with rounds failed")
	}

	res, err = CheckPassword([]byte("$1$wuIXYcHV$1ufSGHoD0EkWPr75i52ST/"), password)
	if err != nil {
		t.Fatalf("md5 error: %s", err)
	}
	if !res {
		t.Fatalf("Password check for md5 failed")
	}

	res, err = CheckPassword([]byte("$3$$4a1fab8f6b5441e0493dc7d41304bfb6"), password)
	if err != nil {
		t.Fatalf("nt error: %s", err)
	}
	if !res {
		t.Fatalf("Password check for nt failed")
	}

	res, err = CheckPassword([]byte("$5$AsETvlsIoaTP3w6G$OZY9mWRFXR9Pz0Xv1pS2TS/QCpxECLEG/dru/Y.nba/"), password)
	if err != nil {
		t.Fatalf("sha256 error: %s", err)
	}
	if !res {
		t.Fatalf("Password check for sha256 failed")
	}

	res, err = CheckPassword([]byte("$5$rounds=243006$oCvhLw/Nn9HuQIm4$VPKzWx9t.NHgmNpVHeSpzQ5y01z4BE14J.bvG8g2yi."), password)
	if err != nil {
		t.Fatalf("sha256 with rounds error: %s", err)
	}
	if !res {
		t.Fatalf("Password check for sha256 with rounds failed")
	}

	res, err = CheckPassword([]byte("$6$zt7D9I3Uu.EhrzEv$j50OCJ3oNdO2Ee7RE9XTDF7dhvrgRwc9NmjJUouk7czn4JTc/A6qLJIT1pMk7FUlTCYCLl6uBHm5NoEboAzIo0"), password)
	if err != nil {
		t.Fatalf("sha512 error: %s", err)
	}
	if !res {
		t.Fatalf("Password check for sha512 failed")
	}

	res, err = CheckPassword([]byte("$6$rounds=523044$.zMtRwbPP2sDg5a5$YgKUnqEda6wxkvDMbJoNjNBiFNpX7nP/uDFV3jV4ngmrXlFBua3n8oIi5St/Re8H3WOksLaody3eAhaGtAN0c/"), password)
	if err != nil {
		t.Fatalf("sha512 with rounds error: %s", err)
	}
	if !res {
		t.Fatalf("Password check for sha512 with rounds failed")
	}

	res, err = CheckPassword([]byte("$7$CU..../....PpL3ULxY5DvYyvasS/a4a0$jqgg90svZLt5KQqFTwegHSn1pXU.aKDavZ3Eq8t2wx9"), password)
	if err != nil {
		t.Fatalf("scrypt error: %s", err)
	}
	if !res {
		t.Fatalf("Password check for scrypt failed")
	}

	res, err = CheckPassword([]byte("$y$j9T$G/uoZu1orhwOE/lUtohEa.$SMu/wxtyhBLa5xeRLVnznBx5vE0/VxY7rJZlQX27N84"), password)
	if err != nil {
		t.Fatalf("yes crypt error: %s", err)
	}
	if !res {
		t.Fatalf("Password check for yes crypt failed")
	}

	res, err = CheckPassword([]byte("$gy$j9T$etkZHzB483TIuw/58Df.N/$7DjHx/8jx.E/VLdyzMIIOJULHoZJ1PNlFl71KXaf0s7"), password)
	if err != nil {
		t.Fatalf("gost yes crypt error: %s", err)
	}
	if !res {
		t.Fatalf("Password check for gost yes crypt failed")
	}

	// Confirm new password generation works.
	var passwd PasswdInterface
	var hash []byte

	passwd = NewSHA1Passwd()
	hash, err = passwd.HashPassword(password)
	if err != nil {
		t.Fatalf("sha1 error: %s", err)
	}
	fmt.Println("sha1:", string(hash))

	passwd = NewSunMD5Passwd()
	hash, err = passwd.HashPassword(password)
	if err != nil {
		t.Fatalf("sun md5 error: %s", err)
	}
	fmt.Println("sun md5:", string(hash))

	passwd = NewSHA256CryptPasswd()
	hash, err = passwd.HashPassword(password)
	if err != nil {
		t.Fatalf("sha256 error: %s", err)
	}
	fmt.Println("sha256:", string(hash))

	passwd = NewSHA512CryptPasswd()
	hash, err = passwd.HashPassword(password)
	if err != nil {
		t.Fatalf("sha512 error: %s", err)
	}
	fmt.Println("sha512:", string(hash))

	passwd = NewSCryptPasswd()
	hash, err = passwd.HashPassword(password)
	if err != nil {
		t.Fatalf("scrypt error: %s", err)
	}
	fmt.Println("scrypt:", string(hash))

	passwd = NewYesCryptPasswd()
	hash, err = passwd.HashPassword(password)
	if err != nil {
		t.Fatalf("yes crypt error: %s", err)
	}
	fmt.Println("yes crypt:", string(hash))

	passwd = NewGostYesCryptPasswd()
	hash, err = passwd.HashPassword(password)
	if err != nil {
		t.Fatalf("gost yes crypterror: %s", err)
	}
	fmt.Println("gost yes crypt:", string(hash))
}
