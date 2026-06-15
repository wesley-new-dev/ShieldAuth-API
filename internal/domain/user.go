package domain

import (
	"net/mail"
	"strings"
)

type User struct {
	Id 				int64
	Name 			string
	Email 			string
	PasswordHash 	[]byte
}


func NewUser(name, email string, passwordHash []byte) (*User, error) {
	cleanName := strings.TrimSpace(name)
	cleanEmail := strings.TrimSpace(strings.ToLower(email))

	if cleanName == "" {
		return nil, ErrInvalidCredentials
	}

	err := isValidEmail(email)
	if err != nil {
		return nil, ErrInvalidEmailFormat
	}

	return &User{
		Name: cleanName,
		Email: cleanEmail,
		PasswordHash: passwordHash,
	}, nil
}

func RestoreUser(
	id 				int64,
	name 			string,
	email 			string,
	passwordHash 	[]byte,
) *User {
	return &User{
		Id: id,
		Name: name,
		Email: email,
		PasswordHash: passwordHash,
	}
}

func (u *User) ChangeEmail(currentEmail, newEmail, confirmNewEmail string) error {
	currentEmail = strings.TrimSpace(strings.ToLower(currentEmail))
	newEmail = strings.TrimSpace(strings.ToLower(newEmail))
	confirmNewEmail = strings.TrimSpace(strings.ToLower(confirmNewEmail))

	if !strings.EqualFold(currentEmail, u.Email) {
		return ErrEmailMismatch
	}

	if newEmail != confirmNewEmail {
		return ErrEmailMismatch
	}

	if strings.EqualFold(newEmail, u.Email) {
		return ErrEmailIsTheSame
	}

	err := isValidEmail(newEmail)
	if err != nil {
		return ErrInvalidEmailFormat
	}
	

	u.Email = newEmail
	return nil
}


func (u *User) ChangeName(currentName, newName string) error {
	currentName = strings.TrimSpace(currentName)
	newName = strings.TrimSpace(newName)

	if !strings.EqualFold(currentName, u.Name) {
		return ErrInvalidCredentials
	}

	if strings.EqualFold(newName, u.Name) {
		return ErrNameIsTheSame
	}

	if newName == "" {
		return ErrInvalidCredentials
	}

	u.Name = newName
	return nil
}

func isValidEmail(email string) error {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return err
	}

	parts := strings.Split(addr.Address, "@")
	if len(parts) != 2 {
		return err
	}

	if !strings.EqualFold(parts[1], "example.com") {
		return err
	}

	return nil
}