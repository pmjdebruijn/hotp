package hotp

import "testing"
import "crypto/sha1"
import "crypto/sha256"
import "crypto/sha512"

func TestValue(t *testing.T) {
  // from https://www.ietf.org/rfc/rfc4226.txt page 32
  rfc4226_sha1_secret := []byte("12345678901234567890")
  rfc4226_sha1_values := map[uint64]string{
              0:"755224",
              1:"287082",
              2:"359152",
              3:"969429",
              4:"338314",
              5:"254676",
              6:"287922",
              7:"162583",
              8:"399871",
              9:"520489",
   };

  for count, expect := range rfc4226_sha1_values {
    result := Value(sha1.New, rfc4226_sha1_secret, count, 6)
    if (result != expect) {
      t.Error("rfc4226 counter", count, "expected", expect, "result", result)
    }
  }

  // from https://tools.ietf.org/html/rfc6238 page 15
  rfc6238_sha1_secret := []byte("12345678901234567890")
  rfc6238_sha1_values := map[uint64]string{
             59:"94287082",
     1111111109:"07081804",
     1111111111:"14050471",
     1234567890:"89005924",
     2000000000:"69279037",
    20000000000:"65353130",
  };

  for count, expect := range rfc6238_sha1_values {
    result := Value(sha1.New, rfc6238_sha1_secret, count / 30, 8)
    if (result != expect) {
      t.Error("rfc6238 sha1 counter", count, "expected", expect, "result", result)
    }
  }

  // from https://tools.ietf.org/html/rfc6238 page 15, with errata'd secret key
  rfc6238_sha256_secret := []byte("12345678901234567890123456789012")
  rfc6238_sha256_values := map[uint64]string{
             59:"46119246",
     1111111109:"68084774",
     1111111111:"67062674",
     1234567890:"91819424",
     2000000000:"90698825",
    20000000000:"77737706",
  };

  for count, expect := range rfc6238_sha256_values {
    result := Value(sha256.New, rfc6238_sha256_secret, count / 30, 8)
    if (result != expect) {
      t.Error("rfc6238 sha256 counter", count, "expected", expect, "result", result)
    }
  }

  // from https://tools.ietf.org/html/rfc6238 page 15, with errata'd secret key
  rfc6238_sha512_secret := []byte("1234567890123456789012345678901234567890123456789012345678901234")
  rfc6238_sha512_values := map[uint64]string{
             59:"90693936",
     1111111109:"25091201",
     1111111111:"99943326",
     1234567890:"93441116",
     2000000000:"38618901",
    20000000000:"47863826",
  };

  for count, expect := range rfc6238_sha512_values {
    result := Value(sha512.New, rfc6238_sha512_secret, count / 30, 8)
    if (result != expect) {
      t.Error("rfc6238 sha512 counter", count, "expected", expect, "result", result)
    }
  }

}
