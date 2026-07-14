package security

import (
	"errors"
	"github.com/awnumar/memguard"
)

type SensitiveData struct {
	enclave *memguard.Enclave
}

func NewSensitiveData(raw []byte) (*SensitiveData, error) {
	if len(raw) == 0 {
		return nil, errors.New("the original data cannot be empty")
	}

	enclave := memguard.NewEnclave(raw)
	clear(raw)

	return &SensitiveData{enclave: enclave}, nil
}

func (s *SensitiveData) ExecuteWithDecrypted(function func(decrypteBytes []byte) error) error {
	if s.enclave == nil {
		return errors.New("")
	}

	lockedBuffer, err := s.enclave.Open()
	if err != nil {
		return err
	}
	defer lockedBuffer.Destroy()

	return function(lockedBuffer.Bytes())
}
