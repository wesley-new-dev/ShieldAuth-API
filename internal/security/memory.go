package security

import "runtime"

func ZeroMemory(b []byte) {
	for i := range b {
		b[i] = 0
	}

	runtime.KeepAlive(b)
}