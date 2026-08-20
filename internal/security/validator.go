package security

import (
	"unicode/utf8"

	"ShieldAuth-API/internal/domain"
	
	"github.com/nbutton23/zxcvbn-go"
)

func VerifyPasswordAdvanced(password []byte, userInputs []string) error {
	stringPassword := string(password)

	length := utf8.RuneCount(password)

	if length < 12 {
		return domain.ErrShortPassword
	}

	if length > 128 {
		return domain.ErrLongPassword
	}

	analysis := zxcvbn.PasswordStrength(stringPassword, userInputs)
	if analysis.Score < 3 {
		return domain.ErrWeakPassword
	}

	return nil
}
