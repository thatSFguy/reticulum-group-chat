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
	Hash           string    `json:"-"` // hex, populated on load
	Nickname       string    `json:"nickname"`
	JoinedAt       time.Time `json:"joined_at"`
	LastAnnounceAt time.Time `json:"last_announce_at,omitempty"`
	LastMessageAt  time.Time `json:"last_message_at,omitempty"`

	// LastCommandAt records the last time we saw any inbound traffic from
	// the member that ISN'T a forwarded chat message — a command (/list,
	// /nick, …), an over-limit message, or a message while paused. It keeps
	// a demonstrably present member off the idle-prune sweep (LastSeen) but
	// deliberately does NOT count toward LastSpoke, so running commands can
	// never save a lurker from the silent-prune sweep. (/join is the one
	// "command" that still counts as speaking — it goes through AddOrUpdate,
	// which sets LastMessageAt.)
	LastCommandAt time.Time `json:"last_command_at,omitempty"`

	// Paused: when true, the forwarder skips this user when fanning out
	// messages, and rejects their non-command messages with a "you're
	// paused" reply rather than forwarding. Toggled via /pause /resume.
	Paused bool `json:"paused,omitempty"`

	// TextOnly: when true, the forwarder strips LXMF non-text fields
	// (FIELD_IMAGE, etc.) before delivering to this user — they still
	// receive the text body of every group message but no image/audio/
	// file attachments. For roster members on low-bandwidth links (LoRa,
	// metered cellular) who want to stay in the conversation without
	// paying for every photo. Toggled via /textonly and /showall.
	TextOnly bool `json:"text_only,omitempty"`

	// Invited marks a member who was added administratively — via
	// /adduser, or auto-enrolled at startup as a config admin/mod — rather
	// than by joining themselves, and has not yet been heard from directly
	// (no inbound message, command, or announce since being added). Exempt
	// from pruning — a locked-group invitee who takes weeks to come online
	// must not be swept before they ever connect. The flag is cleared the
	// first time we hear from them (Touch, MarkMessage, or a fresh
	// UpdateLastAnnounce), after which normal prune rules apply. Empty
	// (false) for everyone who joined the ordinary way.
	Invited bool `json:"invited,omitempty"`

	// Role is the runtime-granted privilege level: "" (regular user),
	// "mod", or "admin". Set via /usermode and persisted here. It is a
	// floor-raiser, not the source of truth: the effective role is the
	// max of this and the config admins/mods lists, so a config-granted
	// role can never be demoted from within the chat (edit the config
	// for that). Empty for the overwhelming majority of users.
	Role string `json:"role,omitempty"`
}

// LastSeen reports the most recent moment we have evidence the user was
// present: the latest of their join, last message, and last announce.
//
// JoinedAt is a floor so a member who just joined (or one loaded from a
// state file predating the last_message_at/last_announce_at fields) is
// never swept by Prune before they've had a chance to send a message or
// announce — without it those users would carry a zero LastSeen and be
// pruned on the first tick.
func (u User) LastSeen() time.Time {
	last := u.JoinedAt
	if u.LastMessageAt.After(last) {
		last = u.LastMessageAt
	}
	if u.LastAnnounceAt.After(last) {
		last = u.LastAnnounceAt
	}
	if u.LastCommandAt.After(last) {
		last = u.LastCommandAt
	}
	return last
}

// LastSpoke reports the most recent moment the user contributed a chat
// message to the group (or joined). It deliberately IGNORES both announces
// AND commands: a member whose Reticulum client keeps re-announcing in the
// background, or who only ever runs read-only commands like /list, but who
// never actually says anything, still registers as silent. This is what the
// silent-prune policy keys on, so a lurker who joined and went quiet is
// swept even while their client is on the air and they poke at commands.
//
// JoinedAt is a floor for the same reason as in LastSeen — a member loaded
// from a state file predating last_message_at carries a zero LastMessageAt
// and must fall back to their join time rather than the epoch.
func (u User) LastSpoke() time.Time {
	last := u.JoinedAt
	if u.LastMessageAt.After(last) {
		last = u.LastMessageAt
	}
	return last
}

type Roster struct {
	mu      sync.Mutex
	users   map[string]*User // key: lowercase hex hash
	banlist map[string]struct{}
	store   *Store

	// dirty marks state changed by deferPersistLocked (the announce
	// path) but not yet written. Cleared by any persist. See Flush.
	dirty bool
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

// AddInvited adds a member who was placed in the roster by an admin/mod
// via /adduser, rather than by joining themselves. It stamps JoinedAt
// (so LastSeen has a sane floor) but deliberately does NOT set
// LastMessageAt — the invitee has not spoken — and marks them Invited so
// Prune skips them until they're first heard from. Returns true if this
// call introduced a new member; if the hash is already in the roster it
// is left untouched and returns false.
func (r *Roster) AddInvited(hashBytes []byte, now time.Time) (bool, error) {
	h, err := normalizeHash(hashBytes)
	if err != nil {
		return false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.users[h]; exists {
		return false, nil
	}
	r.users[h] = &User{
		Hash:     h,
		JoinedAt: now,
		Invited:  true,
	}
	return true, r.persistLocked()
}

// Touch refreshes last_command_at for an existing member so the idle-prune
// sweep (LastSeen) counts them as present. Unlike AddOrUpdate it never
// creates a user — it's a no-op for non-members (returns false). Used for
// any inbound traffic from a member that isn't a forwarded chat message
// (commands, over-limit messages, messages while paused).
//
// Crucially it does NOT touch last_message_at, so this kind of traffic does
// not count toward LastSpoke — a member who only ever runs commands is
// still eligible for the silent-prune sweep. Use MarkMessage for an actual
// chat message.
func (r *Roster) Touch(hashBytes []byte, now time.Time) (bool, error) {
	h, err := normalizeHash(hashBytes)
	if err != nil {
		return false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[h]
	if !ok {
		return false, nil
	}
	u.LastCommandAt = now
	u.Invited = false // heard from them — they're a full member now
	// Deferred like the announce path: this fires on EVERY inbound
	// message, and a synchronous whole-roster marshal per message is
	// pure amplification. Activity timestamps only drive multi-week
	// prune windows, so losing the most recent one to a hard kill is
	// harmless — the next message re-stamps it.
	r.deferPersistLocked()
	return true, nil
}

// MarkMessage refreshes last_message_at for an existing member — the signal
// that they contributed an actual chat message to the group. This is the
// only inbound path (besides /join's AddOrUpdate) that counts toward
// LastSpoke, and so the only one that resets the silent-prune clock. Like
// Touch it never creates a user (non-members are invited, not auto-joined);
// it's a no-op returning false for a non-member.
func (r *Roster) MarkMessage(hashBytes []byte, now time.Time) (bool, error) {
	h, err := normalizeHash(hashBytes)
	if err != nil {
		return false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[h]
	if !ok {
		return false, nil
	}
	u.LastMessageAt = now
	u.Invited = false // heard from them — they're a full member now
	r.deferPersistLocked() // see Touch
	return true, nil
}

// UpdateLastAnnounce only refreshes existing users; announces from
// non-members do not auto-join (that's reserved for actual messages).
//
// `at` is the announce's EMISSION time (decoded from the signed
// random_hash), not the moment we received it — see announceTap.OnAnnounce.
// The update is monotonic: it only ever advances last_announce_at, never
// moves it backward. This is what defeats stale-announce replay. Reticulum
// transport nodes legitimately re-emit cached announces (path responses,
// retransmits) long after the original announcer is gone; those replays
// carry the original, old emission time, so taking the max means a replay
// can't make a long-dead identity look freshly active and dodge Prune.
// As a bonus it skips the disk write entirely when a replay doesn't
// advance the timestamp.
func (r *Roster) UpdateLastAnnounce(hashBytes []byte, at time.Time) error {
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
	if !at.After(u.LastAnnounceAt) {
		return nil
	}
	u.LastAnnounceAt = at
	u.Invited = false // a fresh announce is real presence — full member now
	// Deferred: this runs on the packet dispatcher. Losing an
	// announce timestamp to a hard kill is harmless — the next announce
	// re-stamps it, and the value only feeds prune decisions on a
	// multi-week horizon.
	r.deferPersistLocked()
	return nil
}

// Prune removes a user when EITHER inactivity rule fires:
//
//   - idle: their LastSeen (message, command, OR announce) is older than
//     now-idleCutoff. This sweeps members who have left the network
//     entirely — nothing has been heard from them or their client.
//
//   - silent: their LastSpoke (message or command, IGNORING announces) is
//     older than now-silentCutoff. This sweeps lurkers who joined and went
//     quiet but whose client keeps announcing, so the idle rule alone would
//     never catch them. Disabled when silentCutoff <= 0.
//
// silentCutoff is normally the larger window (e.g. idle 4w, silent 6w):
// a member who is both gone and silent is caught by the shorter idle rule
// first; the silent rule only adds value for members who are present
// (announcing) but contribute nothing.
//
// Returns the hashes pruned.
func (r *Roster) Prune(now time.Time, idleCutoff, silentCutoff time.Duration) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	idleThreshold := now.Add(-idleCutoff)
	silentThreshold := now.Add(-silentCutoff)
	var pruned []string
	for h, u := range r.users {
		// An admin-added invitee we've never heard from is exempt: they
		// must not be swept before they've had the chance to come online.
		// The flag clears on first contact, after which they prune normally.
		if u.Invited {
			continue
		}
		idle := u.LastSeen().Before(idleThreshold)
		silent := silentCutoff > 0 && u.LastSpoke().Before(silentThreshold)
		if idle || silent {
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

// SetPaused toggles the user's paused flag. Returns an error if the user
// isn't in the roster.
func (r *Roster) SetPaused(hashHex string, paused bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[strings.ToLower(hashHex)]
	if !ok {
		return fmt.Errorf("user not in roster")
	}
	u.Paused = paused
	return r.persistLocked()
}

// IsPaused returns true iff the user is in the roster and currently paused.
func (r *Roster) IsPaused(hashHex string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[strings.ToLower(hashHex)]
	return ok && u.Paused
}

// SetTextOnly toggles the user's text-only flag. Returns an error if the
// user isn't in the roster. See User.TextOnly for the policy semantics.
func (r *Roster) SetTextOnly(hashHex string, textOnly bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[strings.ToLower(hashHex)]
	if !ok {
		return fmt.Errorf("user not in roster")
	}
	u.TextOnly = textOnly
	return r.persistLocked()
}

// SetRole sets (or, with role=="", clears) the user's runtime-granted
// role. Returns an error if the user isn't in the roster. Accepts only
// "", "mod", or "admin"; any other value is rejected. See User.Role for
// the floor semantics — this never lowers a config-granted role.
func (r *Roster) SetRole(hashHex, role string) error {
	switch role {
	case "", "mod", "admin":
	default:
		return fmt.Errorf("invalid role %q", role)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[strings.ToLower(hashHex)]
	if !ok {
		return fmt.Errorf("user not in roster")
	}
	u.Role = role
	return r.persistLocked()
}

// IsTextOnly returns true iff the user is in the roster and has opted
// into text-only delivery.
func (r *Roster) IsTextOnly(hashHex string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[strings.ToLower(hashHex)]
	return ok && u.TextOnly
}

// ActiveHashes returns the hex hashes of all roster members whose Paused
// flag is false. The forwarder uses this to decide who receives a fanned-
// out message.
func (r *Roster) ActiveHashes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.users))
	for h, u := range r.users {
		if !u.Paused {
			out = append(out, h)
		}
	}
	return out
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

// Len returns the current member count (including paused members). Used
// to enforce service.max_members.
func (r *Roster) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.users)
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

// deferPersistLocked marks state dirty WITHOUT writing. Used only by
// the announce path, which runs on the Transport dispatcher goroutine:
// a synchronous whole-roster marshal + write there blocks every inbound
// packet and outbound delivery proof queued behind it — the same
// failure the announce cache was moved off the dispatcher to avoid.
// Flush (called on a timer and at shutdown) does the write.
// Callers must hold r.mu.
func (r *Roster) deferPersistLocked() {
	if r.store != nil {
		r.dirty = true
	}
}

// Flush writes roster state if a deferred change is outstanding. Safe
// to call concurrently; a no-op when nothing changed.
func (r *Roster) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.dirty {
		return nil
	}
	return r.persistLocked()
}

func (r *Roster) persistLocked() error {
	if r.store == nil {
		return nil
	}
	// Any write covers every pending deferred change.
	r.dirty = false
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
