package service

type ValidTokenService struct {
	resetStore ResetStore
}

func NewValidToken(resetStore ResetStore) *ValidTokenService {
	return &ValidTokenService{
		resetStore: resetStore,
	}
}