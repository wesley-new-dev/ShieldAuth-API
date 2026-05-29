package security

import (
	"bytes"
	"runtime"
	"unsafe"
)

type SecretBytes []byte

func (s *SecretBytes) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		return nil
	}

	if b[0] == '"' && b[len(b)-1] == '"' {
		b = b[1 : len(b)-1]
	}

	dst := make([]byte, len(b))
	copy(dst, b)

	*s = dst
	return nil
}

func ZeroMemory(b []byte) {
	if len(b) == 0 {
		return
	}

	for i := range b {
		b[i] = 0
	}

	_ = *(*byte)(unsafe.Pointer(&b[0]))

	runtime.KeepAlive(b)
}