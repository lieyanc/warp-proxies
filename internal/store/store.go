package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

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
	accPath := filepath.Join(s.dir, "accounts.json")
	if data, err := os.ReadFile(accPath); err == nil {
		if err := json.Unmarshal(data, &s.accounts); err != nil {
			return err
		}
	}
	setPath := filepath.Join(s.dir, "settings.json")
	if data, err := os.ReadFile(setPath); err == nil {
		if err := json.Unmarshal(data, &s.settings); err != nil {
			return err
		}
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
	return nil
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
