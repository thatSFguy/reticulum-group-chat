package roster

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type User struct {
	Hash            string    `json:"-"`                  // hex, populated on load
	Nickname        string    `json:"nickname"`
	JoinedAt        time.Time `json:"joined_at"`
	LastAnnounceAt  time.Time `json:"last_announce_at,omitempty"`
	LastMessageAt   time.Time `json:"last_message_at,omitempty"`
}

func (u User) LastSeen() time.Time {
	if u.LastAnnounceAt.After(u.LastMessageAt) {
		return u.LastAnnounceAt
	}
	return u.LastMessageAt
}

type Roster struct {
	mu      sync.Mutex
	users   map[string]*User // key: lowercase hex hash
	banlist map[string]struct{}
	store   *Store
}

func New(store *Store) (*Roster, error) {
	r := &Roster{
		users:   map[string]*User{},
		banlist: map[string]struct{}{},
		store:   store,
	}
	if store != nil {
		state, err := store.Load()
		if err != nil {
			return nil, err
		}
		for h, u := range state.Users {
			u.Hash = h
			r.users[h] = u
		}
		for _, h := range state.Banlist {
			r.banlist[strings.ToLower(h)] = struct{}{}
		}
	}
	return r, nil
}

// AddOrUpdate registers a message-time event for the user with the given
// 16-byte identity hash. Returns true if this call introduced a new user
// (or revived a kicked/pruned user, which we treat the same way for
// replay-on-join purposes).
func (r *Roster) AddOrUpdate(hashBytes []byte, now time.Time) (bool, error) {
	h, err := normalizeHash(hashBytes)
	if err != nil {
		return false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	u, exists := r.users[h]
	if !exists {
		u = &User{
			Hash:     h,
			JoinedAt: now,
		}
		r.users[h] = u
	}
	u.LastMessageAt = now
	return !exists, r.persistLocked()
}

// UpdateLastAnnounce only refreshes existing users; announces from
// non-members do not auto-join (that's reserved for actual messages).
func (r *Roster) UpdateLastAnnounce(hashBytes []byte, now time.Time) error {
	h, err := normalizeHash(hashBytes)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[h]
	if !ok {
		return nil
	}
	u.LastAnnounceAt = now
	return r.persistLocked()
}

// Prune removes any user whose last_seen is older than `now - cutoff`.
// Returns the hashes pruned.
func (r *Roster) Prune(now time.Time, cutoff time.Duration) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	threshold := now.Add(-cutoff)
	var pruned []string
	for h, u := range r.users {
		if u.LastSeen().Before(threshold) {
			delete(r.users, h)
			pruned = append(pruned, h)
		}
	}
	if len(pruned) == 0 {
		return nil, nil
	}
	return pruned, r.persistLocked()
}

// Remove drops a user from the roster (the kick path). Idempotent.
func (r *Roster) Remove(hashHex string) (bool, error) {
	h := strings.ToLower(hashHex)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[h]; !ok {
		return false, nil
	}
	delete(r.users, h)
	return true, r.persistLocked()
}

func (r *Roster) Has(hashBytes []byte) bool {
	h, err := normalizeHash(hashBytes)
	if err != nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.users[h]
	return ok
}

func (r *Roster) Get(hashHex string) (User, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[strings.ToLower(hashHex)]
	if !ok {
		return User{}, false
	}
	return *u, true
}

func (r *Roster) SetNickname(hashHex, nick string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[strings.ToLower(hashHex)]
	if !ok {
		return fmt.Errorf("user not in roster")
	}
	u.Nickname = nick
	return r.persistLocked()
}

// List returns a snapshot of users sorted by nickname (case-insensitive),
// users without a nickname falling to the bottom by hash.
func (r *Roster) List() []User {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]User, 0, len(r.users))
	for _, u := range r.users {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool {
		ni, nj := strings.ToLower(out[i].Nickname), strings.ToLower(out[j].Nickname)
		switch {
		case ni == "" && nj != "":
			return false
		case ni != "" && nj == "":
			return true
		case ni != nj:
			return ni < nj
		default:
			return out[i].Hash < out[j].Hash
		}
	})
	return out
}

// Hashes returns a snapshot of every roster member's hash.
func (r *Roster) Hashes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.users))
	for h := range r.users {
		out = append(out, h)
	}
	return out
}

// Resolve finds a user by nickname (case-insensitive) or by a hex prefix
// of length >= 4. Returns ambiguity error if multiple match.
func (r *Roster) Resolve(query string) (User, error) {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return User{}, fmt.Errorf("empty user identifier")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	var byNick []*User
	for _, u := range r.users {
		if strings.ToLower(u.Nickname) == q {
			byNick = append(byNick, u)
		}
	}
	if len(byNick) == 1 {
		return *byNick[0], nil
	}
	if len(byNick) > 1 {
		return User{}, ambiguousErr(q, byNick)
	}

	if isHexPrefix(q) && len(q) >= 4 {
		var byHash []*User
		for _, u := range r.users {
			if strings.HasPrefix(u.Hash, q) {
				byHash = append(byHash, u)
			}
		}
		if len(byHash) == 1 {
			return *byHash[0], nil
		}
		if len(byHash) > 1 {
			return User{}, ambiguousErr(q, byHash)
		}
	}
	return User{}, fmt.Errorf("no user matches %q", query)
}

// Ban adds a hash to the banlist and removes the user from the roster.
func (r *Roster) Ban(hashHex string) error {
	h := strings.ToLower(hashHex)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.banlist[h] = struct{}{}
	delete(r.users, h)
	return r.persistLocked()
}

func (r *Roster) Unban(hashHex string) (bool, error) {
	h := strings.ToLower(hashHex)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.banlist[h]; !ok {
		return false, nil
	}
	delete(r.banlist, h)
	return true, r.persistLocked()
}

func (r *Roster) IsBanned(hashBytes []byte) bool {
	h, err := normalizeHash(hashBytes)
	if err != nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.banlist[h]
	return ok
}

func (r *Roster) Banlist() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.banlist))
	for h := range r.banlist {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func (r *Roster) persistLocked() error {
	if r.store == nil {
		return nil
	}
	state := State{
		Users:   make(map[string]*User, len(r.users)),
		Banlist: make([]string, 0, len(r.banlist)),
	}
	for h, u := range r.users {
		state.Users[h] = u
	}
	for h := range r.banlist {
		state.Banlist = append(state.Banlist, h)
	}
	sort.Strings(state.Banlist)
	return r.store.Save(state)
}

func normalizeHash(hashBytes []byte) (string, error) {
	if len(hashBytes) != 16 {
		return "", fmt.Errorf("identity hash must be 16 bytes (got %d)", len(hashBytes))
	}
	return hex.EncodeToString(hashBytes), nil
}

func isHexPrefix(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func ambiguousErr(q string, matches []*User) error {
	parts := make([]string, 0, len(matches))
	for _, u := range matches {
		label := u.Nickname
		if label == "" {
			label = u.Hash[:8]
		} else {
			label = fmt.Sprintf("%s (%s)", u.Nickname, u.Hash[:8])
		}
		parts = append(parts, label)
	}
	sort.Strings(parts)
	return fmt.Errorf("%q is ambiguous: %s", q, strings.Join(parts, ", "))
}
