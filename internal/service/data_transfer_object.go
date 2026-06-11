package service

type RegisterInput struct {
	Name     	string
	Email    	string
	Password 	[]byte
}

type LoginInput struct {
	Name     	string
	Email    	string
	Password 	[]byte
}

type ResetPasswordInput struct {
	Token           string
	NewPassword     []byte
	ConfirmPassword []byte
}

type ChangeNameInput struct {
	ID             	int
	CurrentName    	string
	NewName        	string
	ConfirmNewName 	string
}

type ChangeEmailInput struct {
	ID             	int
	CurrentEmail    string
	NewEmail        string
	ConfirmNewEmail string
	Password        []byte
}

type ChangePasswordInput struct {
	UserID 				int
	CurrentPassword 	[]byte
	NewPassword 		[]byte
	ConfirmPassword 	[]byte
}

type DeleteAccountInput struct {
	UserID 				int
	CurrentPassword 	[]byte
}

type LogOutInput struct {
	UserID 				int
	CurrentPassword 	[]byte
}