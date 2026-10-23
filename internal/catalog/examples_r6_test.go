package catalog

import (
	"reflect"
	"testing"
)

// N1, N2: a connection string password such as Pwd=... is a credential in the
// file readers too. Only a standalone PWD or OLDPWD whose value is an absolute
// path (the sudo audit record, an environment dump) stays readable.
func TestExampleFileReadersRedactPwdWithoutPathValue(t *testing.T) {
	c := loadExamples(t)
	for _, name := range pwdFileReaders {
		r := exampleRedactor(t, c, name)
		checkRedactionCases(t, name, r, []redactionCase{
			{"Server=db;Uid=app;Pwd=LEAKN99", "LEAKN99"},
			{"uid=app;pwd=LEAKN98", "LEAKN98"},
			{"Pwd=LEAKN97", "LEAKN97"},
			{"PWD = LEAKN96", "LEAKN96"},
			{"pwd: LEAKN95", "LEAKN95"},
			{`pwd="LEAKN94"`, "LEAKN94"},
			{"oldpwdx=LEAKN103", "LEAKN103"},
			{"OLDPWD=LEAKN102", "LEAKN102"},
			{"oldpwd_file=LEAKN101", "LEAKN101"},
			{"sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/echo pwd=LEAKN106", "LEAKN106"},
			{"PWD=/home/deploy;Uid=app;Pwd=LEAKN107", "LEAKN107"},
			{"sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/id", ""},
			{"PWD=/home/deploy", ""},
			{"OLDPWD=/home/deploy", ""},
			{"OLDPWD=~/work", ""},
			{"pwd=/srv/app", ""},
		})
		sudo := "sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/id"
		if got := r.Line(sudo); got != sudo {
			t.Errorf("%s: sudo record changed: %q", name, got)
		}
	}
}

func TestExampleFileReadersShareOneRuleSet(t *testing.T) {
	c := loadExamples(t)
	want := c.Actions[pwdFileReaders[0]].Redact
	for _, name := range pwdFileReaders[1:] {
		if got := c.Actions[name].Redact; !reflect.DeepEqual(got, want) {
			t.Errorf("%s redact config differs from %s", name, pwdFileReaders[0])
		}
	}
}
