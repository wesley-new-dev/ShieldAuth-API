package service

type RegisterInput struct {
	Name     string
	Email    string
	Password string
}

type LoginInput struct {
	Name     string
	Email    string
	Password string
}

type ResetPasswordInput struct {
	Token           string
	NewPasword      string
	ConfirmPassword string
}

type ChangeNameInput struct {
	ID             int
	CurrentName    string
	NewName        string
	ConfirmNewName string
}

type ChangeEmailInput struct {
	ID             	int
	CurrentEmail    string
	NewEmail        string
	ConfirmNewEmail string
	Password        string
}

type ChangePasswordInput struct {
	UserID 				int
	CurrentPassword 	string
	NewPassword 		string
	ConfirmPassword 	string
}