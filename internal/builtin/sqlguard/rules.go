package sqlguard

// Rule lists. They are variables so that findings about server behavior can
// adjust them without touching the validation logic.

// deniedKeywords are rejected when they appear as an unquoted word anywhere in
// the statement. INTO covers INTO OUTFILE, INTO DUMPFILE and SELECT ... INTO.
// TRUNCATE is also a numeric function, so TRUNCATE( is allowed (see scan).
var deniedKeywords = []string{
	"INSERT", "UPDATE", "DELETE", "MERGE", "CREATE", "DROP", "ALTER", "TRUNCATE", "GRANT", "REVOKE",
	"SET", "RESET", "KILL", "ADMIN", "INSTALL", "UNINSTALL", "LOAD", "EXPORT", "SUBMIT", "CANCEL",
	"REFRESH", "OPTIMIZE", "VACUUM", "ROLLBACK", "COMMIT", "USE", "CALL", "INTO",
}

// Names are lower case. A name is rejected when it is followed by "(",
// whether it is unquoted, quoted or qualified. FILES reads files on the
// backend node, SLEEP blocks, and GET_QUERY_PROFILE returns the statements and
// profiles of other accounts.
var (
	starrocksDeniedFunctions = []string{"files", "sleep", "get_query_profile"}
	dremioDeniedFunctions    = []string{"external_query"}
)

// dremioTableFunctions are the only functions allowed inside TABLE(...) in Dremio.
// They must be unqualified.
var dremioTableFunctions = []string{"table_history", "table_snapshot", "table_manifests", "table_files"}

// showModifiers may precede the SHOW type.
var showModifiers = []string{"FULL", "GLOBAL", "SESSION", "BUILTIN"}

type showType struct {
	name  string
	forms [][]string // alternative keyword sequences that follow SHOW and its modifiers
}

func showT(name string, forms ...string) showType {
	if len(forms) == 0 {
		forms = []string{name}
	}
	t := showType{name: name}
	for _, f := range forms {
		var words []string
		for i, start := 0, 0; i <= len(f); i++ {
			if i == len(f) || f[i] == ' ' {
				if i > start {
					words = append(words, f[start:i])
				}
				start = i + 1
			}
		}
		t.forms = append(t.forms, words)
	}
	return t
}

// The SHOW allow lists. Types that need privileges the query account does not
// have fail on the server; SHOW PROC is not listed.
var (
	starrocksShowTypes = []showType{
		showT("DATABASES", "DATABASES", "SCHEMAS"),
		showT("TABLES"),
		showT("TABLE STATUS"),
		showT("COLUMNS", "COLUMNS", "FIELDS"),
		showT("CATALOGS"),
		showT("CREATE TABLE"),
		showT("CREATE VIEW"),
		showT("CREATE MATERIALIZED VIEW"),
		showT("CREATE DATABASE", "CREATE DATABASE", "CREATE SCHEMA"),
		showT("PARTITIONS"),
		showT("TABLET"),
		showT("MATERIALIZED VIEWS"),
		showT("FUNCTIONS"),
		showT("VARIABLES"),
		showT("STATUS"),
		showT("PROCESSLIST"),
		showT("PROFILELIST"),
		showT("FRONTENDS"),
		showT("BACKENDS"),
		showT("COMPUTE NODES"),
	}
	dremioShowTypes = []showType{
		showT("SCHEMAS", "SCHEMAS", "DATABASES"),
		showT("TABLES"),
		showT("VIEWS"),
		showT("PARTITIONS"),
		showT("FILES"),
		showT("CREATE TABLE"),
		showT("FUNCTIONS"),
	}
)

func showTypesOf(d Dialect) []showType {
	switch d {
	case StarRocks:
		return starrocksShowTypes
	case Dremio:
		return dremioShowTypes
	}
	return nil
}

// ShowTypes returns the normalized SHOW types the dialect allows. A handler
// can validate a show_types restriction against it.
func ShowTypes(d Dialect) []string {
	var names []string
	for _, t := range showTypesOf(d) {
		names = append(names, t.name)
	}
	return names
}

func deniedFunctionsOf(d Dialect) []string {
	switch d {
	case StarRocks:
		return starrocksDeniedFunctions
	case Dremio:
		return dremioDeniedFunctions
	}
	return nil
}
