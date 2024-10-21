// Copyright (C) 2023 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.


// Note: Code here are primarily adapted from
// https://github.com/drakkan/sftpgo/blob/main/internal/dataprovider/dataprovider.go



package authenticator

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"github.com/alexedwards/argon2id"
    yescrypt "github.com/amoghe/go-crypt"
	"github.com/GehirnInc/crypt"
	"github.com/GehirnInc/crypt/apr1_crypt"
	"github.com/GehirnInc/crypt/md5_crypt"
	"github.com/GehirnInc/crypt/sha256_crypt"
	"github.com/GehirnInc/crypt/sha512_crypt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

const (
	md5cryptPwdPrefix         = "$1$"
	md5cryptApr1PwdPrefix     = "$apr1$"
	sha256cryptPwdPrefix      = "$5$"
	sha512cryptPwdPrefix      = "$6$"
	pbkdf2SHA1Prefix          = "$pbkdf2-sha1$"
	pbkdf2SHA256Prefix        = "$pbkdf2-sha256$"
	pbkdf2SHA512Prefix        = "$pbkdf2-sha512$"
	pbkdf2SHA256B64SaltPrefix = "$pbkdf2-b64salt-sha256$"
	md5DigestPwdPrefix        = "{MD5}"
	sha256DigestPwdPrefix     = "{SHA256}"
	sha512DigestPwdPrefix     = "{SHA512}"
)

var (
    argonPwdPrefixes        = []string{"$argon2id$"}
	bcryptPwdPrefixes       = []string{"$2a$", "$2$", "$2x$", "$2y$", "$2b$"}
    yescryptPwdPrefixes     = []string{"$y$"}
    unixPwdPrefixes         = []string{md5cryptPwdPrefix, md5cryptApr1PwdPrefix, sha256cryptPwdPrefix, sha512cryptPwdPrefix}
    pbkdfPwdPrefixes        = []string{pbkdf2SHA1Prefix, pbkdf2SHA256Prefix, pbkdf2SHA512Prefix, pbkdf2SHA256B64SaltPrefix}
	pbkdfPwdB64SaltPrefixes = []string{pbkdf2SHA256B64SaltPrefix}
	digestPwdPrefixes       = []string{"{MD5}", "{SHA256}", "{SHA512}"}
)

func verifyPassword(password string, hashedPwd string) (bool, error) {
    if isStringPrefixInSlice(hashedPwd, bcryptPwdPrefixes) {
        return compareBcryptPasswordAndHash(password, hashedPwd)
    }
	if isStringPrefixInSlice(hashedPwd, argonPwdPrefixes) {
		return argon2id.ComparePasswordAndHash(password, hashedPwd)
    }
	if isStringPrefixInSlice(hashedPwd, unixPwdPrefixes) {
		return compareUnixPasswordAndHash(password, hashedPwd)
    }
	if isStringPrefixInSlice(hashedPwd, yescryptPwdPrefixes) {
		return compareYescryptPassword(password, hashedPwd)
    }
	if isStringPrefixInSlice(hashedPwd, pbkdfPwdPrefixes) {
		return comparePbkdf2PasswordAndHash(password, hashedPwd)
    }
    if isStringPrefixInSlice(hashedPwd, digestPwdPrefixes) {
		return compareDigestPasswordAndHash(password, hashedPwd)
    }
    return false, errors.New("unknown: invalid or unsupported hash format")
}

func isStringPrefixInSlice(obj string, list []string) bool {
	for _, v := range list {
		if strings.HasPrefix(obj, v) {
			return true
		}
	}
	return false
}

func compareBcryptPasswordAndHash(password string, hashedPwd string) (bool, error) {
    err := bcrypt.CompareHashAndPassword([]byte(hashedPwd), []byte(password))
    return err == nil, err
}

func compareYescryptPassword(password string, hashedPwd string) (bool, error) {
	var pwd string
    var err error
    lastIdx := strings.LastIndex(hashedPwd, "$")
	if pwd, err = yescrypt.Crypt(password, hashedPwd[:lastIdx+1]); err != nil {
		return false, err
	}
	return pwd == hashedPwd, nil
}

func compareUnixPasswordAndHash(password string, hashedPwd string) (bool, error) {
	var crypter crypt.Crypter
	if strings.HasPrefix(hashedPwd, sha512cryptPwdPrefix) {
		crypter = sha512_crypt.New()
	} else if strings.HasPrefix(hashedPwd, sha256cryptPwdPrefix) {
		crypter = sha256_crypt.New()
	} else if strings.HasPrefix(hashedPwd, md5cryptPwdPrefix) {
		crypter = md5_crypt.New()
	} else if strings.HasPrefix(hashedPwd, md5cryptApr1PwdPrefix) {
		crypter = apr1_crypt.New()
	} else {
		return false, errors.New("unix crypt: invalid or unsupported hash format")
	}
	if err := crypter.Verify(hashedPwd, []byte(password)); err != nil {
		return false, err
	}
	return true, nil
}

func comparePbkdf2PasswordAndHash(password string, hashedPwd string) (bool, error) {
	vals := strings.Split(hashedPwd, "$")
	if len(vals) != 5 {
		return false, fmt.Errorf("pbkdf2: hash is not in the correct format")
	}
	iterations, err := strconv.Atoi(vals[2])
	if err != nil {
		return false, err
	}
	expected, err := base64.StdEncoding.DecodeString(vals[4])
	if err != nil {
		return false, err
	}
	var salt []byte
	if isStringPrefixInSlice(hashedPwd, pbkdfPwdB64SaltPrefixes) {
		salt, err = base64.StdEncoding.DecodeString(vals[3])
		if err != nil {
			return false, err
		}
	} else {
		salt = []byte(vals[3])
	}
	var hashFunc func() hash.Hash
	if strings.HasPrefix(hashedPwd, pbkdf2SHA256Prefix) || strings.HasPrefix(hashedPwd, pbkdf2SHA256B64SaltPrefix) {
		hashFunc = sha256.New
	} else if strings.HasPrefix(hashedPwd, pbkdf2SHA512Prefix) {
		hashFunc = sha512.New
	} else if strings.HasPrefix(hashedPwd, pbkdf2SHA1Prefix) {
		hashFunc = sha1.New
	} else {
		return false, fmt.Errorf("pbkdf2: invalid or unsupported hash format %v", vals[1])
	}
	df := pbkdf2.Key([]byte(password), salt, iterations, len(expected), hashFunc)
	return subtle.ConstantTimeCompare(df, expected) == 1, nil
}

func compareDigestPasswordAndHash(password string, hashedPwd string) (bool, error) {
	if strings.HasPrefix(hashedPwd, md5DigestPwdPrefix) {
		h := md5.New()
		h.Write([]byte(password))
		return fmt.Sprintf("%s%x", md5DigestPwdPrefix, h.Sum(nil)) == hashedPwd, nil
	}
	if strings.HasPrefix(hashedPwd, sha256DigestPwdPrefix) {
		h := sha256.New()
		h.Write([]byte(password))
		return fmt.Sprintf("%s%x", sha256DigestPwdPrefix, h.Sum(nil)) == hashedPwd, nil
	}
	if strings.HasPrefix(hashedPwd, sha512DigestPwdPrefix) {
		h := sha512.New()
		h.Write([]byte(password))
		return fmt.Sprintf("%s%x", sha512DigestPwdPrefix, h.Sum(nil)) == hashedPwd, nil
	}
	return false, errors.New("digest: invalid or unsupported hash format")
}
