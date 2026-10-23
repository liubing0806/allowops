package api

import (
	"context"
	"strconv"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/store/db"
)

// Identity data access: console users, role mappings, service accounts,
// sessions and login transactions. See sql.go for the statements kept
// hand-written.

type storedUser struct {
	user          *v1.User
	kind, subject string
}

func userFromRow(r db.ConsoleUser) storedUser {
	u := &v1.User{UserId: r.UserID, ProviderId: r.ProviderID, Username: r.Username, Email: r.Email, DisplayName: r.DisplayName, Groups: r.Groups, ManualRoles: r.ManualRoles, Teams: r.Teams}
	u.Revision = strconv.FormatInt(r.Revision, 10)
	return storedUser{u, r.Kind, r.ProviderSubject}
}

// mappedRoles returns the roles mapped from the groups of a user, in group order.
func mappedRoles(ctx context.Context, q querier, provider string, groups []string) ([]string, error) {
	rows, err := db.New(q).ListMappedRoles(ctx, db.ListMappedRolesParams{ProviderID: provider, Groups: groups})
	if err != nil {
		return nil, err
	}
	roles := []string{}
	for _, r := range rows {
		roles = append(roles, r...)
	}
	return roles, nil
}

// getUser reads one console user. A failed read returns an empty user.
func getUser(ctx context.Context, q querier, id string) (storedUser, error) {
	r, err := db.New(q).GetConsoleUser(ctx, id)
	if err != nil {
		return storedUser{user: &v1.User{}}, err
	}
	return userFromRow(r), nil
}

func searchUsers(ctx context.Context, q querier, query string) ([]storedUser, error) {
	rows, err := db.New(q).SearchConsoleUsers(ctx, query)
	if err != nil {
		return nil, err
	}
	items := make([]storedUser, 0, len(rows))
	for _, r := range rows {
		items = append(items, userFromRow(r))
	}
	return items, nil
}

// upsertUser creates a console user or refreshes its email and groups.
func upsertUser(ctx context.Context, q querier, id, provider, subject, kind, email string, groups []string) error {
	return db.New(q).UpsertConsoleUser(ctx, db.UpsertConsoleUserParams{UserID: id, ProviderID: provider, ProviderSubject: subject, Kind: kind, Email: email, Groups: groups})
}

func userIDBySubject(ctx context.Context, q querier, provider, subject string) (string, error) {
	return db.New(q).GetConsoleUserID(ctx, db.GetConsoleUserIDParams{ProviderID: provider, ProviderSubject: subject})
}

func mappingRevision(ctx context.Context, q querier) (int64, error) {
	return db.New(q).GetRoleMappingRevision(ctx)
}

func listRoleMappings(ctx context.Context, q querier) ([]*v1.RoleMapping, error) {
	rows, err := db.New(q).ListRoleMappings(ctx)
	if err != nil {
		return nil, err
	}
	items := []*v1.RoleMapping{}
	for _, r := range rows {
		items = append(items, &v1.RoleMapping{ProviderId: r.ProviderID, Group: r.GroupName, Roles: r.Roles})
	}
	return items, nil
}

// bumpMappingRevision increments the mapping revision when it equals revision
// and reports the number of rows changed.
func bumpMappingRevision(ctx context.Context, q querier, revision int64) (int64, error) {
	return db.New(q).BumpRoleMappingRevision(ctx, revision)
}

func deleteRoleMappings(ctx context.Context, q querier) error {
	return db.New(q).DeleteRoleMappings(ctx)
}

func insertRoleMapping(ctx context.Context, q querier, provider, group string, roles []string) error {
	return db.New(q).InsertRoleMapping(ctx, db.InsertRoleMappingParams{ProviderID: provider, GroupName: group, Roles: roles})
}

// lockMappingState locks the mapping state row and reports whether the
// configured initial mappings were already applied.
func lockMappingState(ctx context.Context, q querier) (bool, error) {
	return db.New(q).LockRoleMappingState(ctx)
}

func markMappingsInitialized(ctx context.Context, q querier) error {
	return db.New(q).MarkRoleMappingsInitialized(ctx)
}

func listRoleNames(ctx context.Context, q querier) ([]*v1.Role, error) {
	rows, err := db.New(q).ListRoleNames(ctx)
	if err != nil {
		return nil, err
	}
	items := []*v1.Role{}
	for _, name := range rows {
		items = append(items, &v1.Role{Name: name})
	}
	return items, nil
}

func accountFromRow(r db.ServiceAccount) *v1.ServiceAccount {
	return &v1.ServiceAccount{AccountId: r.AccountID, Name: r.Name, OwnerUserId: r.OwnerUserID, Description: r.Description, Roles: r.Roles, Teams: r.Teams, Revision: strconv.FormatInt(r.Revision, 10), CreatedAt: stamp(r.CreatedAt.Time)}
}

// accountResult converts a service account read. A failed read returns an empty account.
func accountResult(r db.ServiceAccount, err error) (*v1.ServiceAccount, error) {
	if err != nil {
		return &v1.ServiceAccount{}, err
	}
	return accountFromRow(r), nil
}

func insertAccount(ctx context.Context, q querier, id, name, owner, description string, roles, teams []string) (*v1.ServiceAccount, error) {
	return accountResult(db.New(q).InsertServiceAccount(ctx, db.InsertServiceAccountParams{AccountID: id, Name: name, OwnerUserID: owner, Description: description, Roles: roles, Teams: teams}))
}

func getAccount(ctx context.Context, q querier, id string) (*v1.ServiceAccount, error) {
	return accountResult(db.New(q).GetServiceAccount(ctx, id))
}

func listAccounts(ctx context.Context, q querier) ([]*v1.ServiceAccount, error) {
	rows, err := db.New(q).ListServiceAccounts(ctx)
	if err != nil {
		return nil, err
	}
	items := []*v1.ServiceAccount{}
	for _, r := range rows {
		items = append(items, accountFromRow(r))
	}
	return items, nil
}

// updateAccount changes an account at an expected revision; pgx.ErrNoRows
// means the revision no longer matches.
func updateAccount(ctx context.Context, q querier, id string, revision int64, owner, description string, roles, teams []string) (*v1.ServiceAccount, error) {
	return accountResult(db.New(q).UpdateServiceAccount(ctx, db.UpdateServiceAccountParams{AccountID: id, Revision: revision, OwnerUserID: owner, Description: description, Roles: roles, Teams: teams}))
}

func tokenFromRow(r db.ListServiceAccountTokensRow) *v1.ServiceAccountToken {
	return &v1.ServiceAccountToken{TokenId: r.TokenID, AccountId: r.AccountID, Description: r.Description, CreatedAt: stamp(r.CreatedAt.Time), ExpiresAt: stamp(r.ExpiresAt.Time), LastUsedAt: nullable(r.LastUsedAt), RevokedAt: nullable(r.RevokedAt)}
}

func insertAccountToken(ctx context.Context, q querier, id, account string, tokenHash []byte, description string, expires time.Time) (*v1.ServiceAccountToken, error) {
	r, err := db.New(q).InsertServiceAccountToken(ctx, db.InsertServiceAccountTokenParams{TokenID: id, AccountID: account, TokenHash: tokenHash, Description: description, ExpiresAt: timestamptz(expires)})
	if err != nil {
		return &v1.ServiceAccountToken{}, err
	}
	return tokenFromRow(db.ListServiceAccountTokensRow(r)), nil
}

func listAccountTokens(ctx context.Context, q querier, account string) ([]*v1.ServiceAccountToken, error) {
	rows, err := db.New(q).ListServiceAccountTokens(ctx, account)
	if err != nil {
		return nil, err
	}
	items := []*v1.ServiceAccountToken{}
	for _, r := range rows {
		items = append(items, tokenFromRow(r))
	}
	return items, nil
}

// revokeAccountToken revokes a token and reports the number of rows matched.
func revokeAccountToken(ctx context.Context, q querier, account, token string) (int64, error) {
	return db.New(q).RevokeServiceAccountToken(ctx, db.RevokeServiceAccountTokenParams{AccountID: account, TokenID: token})
}

// touchAccountToken marks a live token as used and returns its account ID.
func touchAccountToken(ctx context.Context, q querier, tokenHash []byte) (string, error) {
	return db.New(q).TouchServiceAccountToken(ctx, tokenHash)
}

func sessionFromRow(r db.GetIdentitySessionRow) *v1.CliSession {
	return &v1.CliSession{SessionId: r.SessionID, UserId: r.UserID, CreatedAt: stamp(r.CreatedAt.Time), ExpiresAt: stamp(r.ExpiresAt.Time), LastUsedAt: nullable(r.LastUsedAt), RevokedAt: nullable(r.RevokedAt)}
}

// touchSession marks a live session as used and returns its ID and CSRF token.
func touchSession(ctx context.Context, q querier, tokenHash []byte, client string) (string, string, error) {
	r, err := db.New(q).TouchIdentitySession(ctx, db.TouchIdentitySessionParams{TokenHash: tokenHash, Client: client})
	return r.SessionID, r.CsrfToken, err
}

func getSession(ctx context.Context, q querier, id string) (*v1.CliSession, error) {
	r, err := db.New(q).GetIdentitySession(ctx, id)
	if err != nil {
		return &v1.CliSession{}, err
	}
	return sessionFromRow(r), nil
}

func insertSession(ctx context.Context, q querier, id, userID string, tokenHash []byte, client, csrf string, expires time.Time) (*v1.CliSession, error) {
	r, err := db.New(q).InsertIdentitySession(ctx, db.InsertIdentitySessionParams{SessionID: id, UserID: userID, TokenHash: tokenHash, Client: client, CsrfToken: csrf, ExpiresAt: timestamptz(expires)})
	if err != nil {
		return &v1.CliSession{}, err
	}
	return sessionFromRow(db.GetIdentitySessionRow(r)), nil
}

func listCliSessions(ctx context.Context, q querier, userID string) ([]*v1.CliSession, error) {
	rows, err := db.New(q).ListCliSessions(ctx, userID)
	if err != nil {
		return nil, err
	}
	items := []*v1.CliSession{}
	for _, r := range rows {
		items = append(items, sessionFromRow(db.GetIdentitySessionRow(r)))
	}
	return items, nil
}

func revokeSession(ctx context.Context, q querier, id string) error {
	return db.New(q).RevokeIdentitySession(ctx, id)
}

// revokeCliSession revokes a CLI session of a user and reports the number of rows matched.
func revokeCliSession(ctx context.Context, q querier, id, userID string) (int64, error) {
	return db.New(q).RevokeCliSession(ctx, db.RevokeCliSessionParams{SessionID: id, UserID: userID})
}

// oidcTransaction is a pending OIDC login read back by its state hash.
type oidcTransaction struct {
	provider, client, nonce, verifier, loopback, cliState, challenge string
}

// lockOidcAdmission serializes OIDC login admission across gateway instances.
func lockOidcAdmission(ctx context.Context, q querier) error {
	return db.New(q).LockOidcAdmission(ctx)
}

func purgeOidcTransactions(ctx context.Context, q querier) error {
	return db.New(q).DeleteExpiredOidcTransactions(ctx)
}

func countOidcTransactions(ctx context.Context, q querier) (int64, error) {
	return db.New(q).CountLiveOidcTransactions(ctx)
}

func insertOidcTransaction(ctx context.Context, q querier, t oidcTransaction, stateHash []byte, expires time.Time) error {
	return db.New(q).InsertOidcTransaction(ctx, db.InsertOidcTransactionParams{StateHash: stateHash, ProviderID: t.provider, Client: t.client, Nonce: t.nonce, ProviderVerifier: t.verifier, LoopbackUri: t.loopback, CliState: t.cliState, CliChallenge: t.challenge, ExpiresAt: timestamptz(expires)})
}

// bindOidcTransaction binds an unbound live transaction to a browser and
// returns its provider, nonce and PKCE verifier.
func bindOidcTransaction(ctx context.Context, q querier, stateHash, bindingHash []byte) (provider, nonce, verifier string, err error) {
	r, err := db.New(q).BindOidcTransaction(ctx, db.BindOidcTransactionParams{StateHash: stateHash, BindingHash: bindingHash})
	return r.ProviderID, r.Nonce, r.ProviderVerifier, err
}

// takeOidcTransaction consumes a live transaction bound to the given browser.
func takeOidcTransaction(ctx context.Context, q querier, stateHash, bindingHash []byte) (oidcTransaction, error) {
	r, err := db.New(q).TakeOidcTransaction(ctx, db.TakeOidcTransactionParams{StateHash: stateHash, BindingHash: bindingHash})
	return oidcTransaction{r.ProviderID, r.Client, r.Nonce, r.ProviderVerifier, r.LoopbackUri, r.CliState, r.CliChallenge}, err
}

func insertCliLoginCode(ctx context.Context, q querier, codeHash []byte, userID, challenge string, expires time.Time) error {
	return db.New(q).InsertCliLoginCode(ctx, db.InsertCliLoginCodeParams{CodeHash: codeHash, UserID: userID, Challenge: challenge, ExpiresAt: timestamptz(expires)})
}

// lockCliLoginCode locks a live code and returns its user and PKCE challenge.
func lockCliLoginCode(ctx context.Context, q querier, codeHash []byte) (string, string, error) {
	r, err := db.New(q).LockCliLoginCode(ctx, codeHash)
	return r.UserID, r.Challenge, err
}

func deleteCliLoginCode(ctx context.Context, q querier, codeHash []byte) error {
	return db.New(q).DeleteCliLoginCode(ctx, codeHash)
}
