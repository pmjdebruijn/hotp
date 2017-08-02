// Copyright 2017 Pascal de Bruijn. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hotp

import "fmt"
import "math"
import "hash"
import "crypto/hmac"
import "crypto/subtle"
import "encoding/binary"
import "strconv"

func Value(h func() hash.Hash, secret []byte, count uint64, length int) string {
  ctr := make([]byte, 8)
  binary.BigEndian.PutUint64(ctr, count)

  mac := hmac.New(h, secret)
  mac.Write(ctr)

  sum := mac.Sum(nil)

  offset := sum[len(sum)-1] & 0x0f

  subset := sum[offset:offset + 4]

  subset[0] = subset[0] & 0x7f

  number := binary.BigEndian.Uint32(subset) % uint32(math.Pow10(length))

  return fmt.Sprintf("%0" + strconv.Itoa(length) + "d", number)
}

func Match(h func() hash.Hash, secret []byte, count uint64, length int, leeway int, token string) bool {
  v := 0

  for i := -leeway; i <= leeway; i++ {
    ref := Value(h, secret, count + uint64(i), length)

    v += subtle.ConstantTimeCompare([]byte(ref), []byte(token))
  }

  return (v > 0)
}
