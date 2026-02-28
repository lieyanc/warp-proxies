package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

var ErrAccountNotFound = errors.New("account not found")

type Store struct {
	mu       sync.RWMutex
	dir      string
	accounts []Account
	settings Settings
}

func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	s := &Store{
		dir:      dir,
		settings: DefaultSettings(),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	// Load accounts
	accPath := filepath.Join(s.dir, "accounts.json")
	if data, err := os.ReadFile(accPath); err == nil {
		if err := json.Unmarshal(data, &s.accounts); err != nil {
			return err
		}
	}

	// Load settings — auto-create with defaults if missing
	setPath := filepath.Join(s.dir, "settings.json")
	data, err := os.ReadFile(setPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// First launch: write default settings
			return s.saveSettings()
		}
		return err
	}
	if err := json.Unmarshal(data, &s.settings); err != nil {
		return err
	}
	return nil
}

func (s *Store) saveAccounts() error {
	data, err := json.MarshalIndent(s.accounts, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, "accounts.json"), data, 0644)
}

func (s *Store) saveSettings() error {
	data, err := json.MarshalIndent(s.settings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, "settings.json"), data, 0644)
}

func (s *Store) GetAccounts() []Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Account, len(s.accounts))
	copy(out, s.accounts)
	return out
}

func (s *Store) GetEnabledAccounts() []Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Account
	for _, a := range s.accounts {
		if a.Enabled {
			out = append(out, a)
		}
	}
	return out
}

func (s *Store) GetAccountByID(id string) (Account, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.accounts {
		if a.ID == id {
			return a, true
		}
	}
	return Account{}, false
}

func (s *Store) FindInnersByOuterID(outerID string) []Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []Account
	for _, a := range s.accounts {
		if a.GoolOuterID == outerID {
			result = append(result, a)
		}
	}
	return result
}

func (s *Store) AddAccount(a Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accounts = append(s.accounts, a)
	return s.saveAccounts()
}

func (s *Store) RemoveAccount(id string) (Account, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, a := range s.accounts {
		if a.ID == id {
			removed := s.accounts[i]
			s.accounts = append(s.accounts[:i], s.accounts[i+1:]...)
			return removed, true, s.saveAccounts()
		}
	}
	return Account{}, false, nil
}

func (s *Store) UpdateAccount(id string, fn func(*Account)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.accounts {
		if s.accounts[i].ID == id {
			fn(&s.accounts[i])
			return s.saveAccounts()
		}
	}
	return ErrAccountNotFound
}

func (s *Store) GetSettings() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settings
}

func (s *Store) SetSettings(settings Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings = settings
	return s.saveSettings()
}
