package logquery

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// cursor marks the first record not returned. It is not signed: a modified
// cursor can only point to other positions of the same source, which the
// caller may read anyway. Since and until pin the resolved range, so a
// relative range does not move between pages.
type cursor struct {
	V      int    `json:"v"`
	Source string `json:"source"`
	Dev    uint64 `json:"dev"`
	Inode  uint64 `json:"ino"`
	Offset int64  `json:"off"`
	Time   string `json:"time"`
	// Seq is the index of the record among the records of a container
	// output stream with the same time; file records use Dev, Inode, Offset.
	Seq   int    `json:"seq,omitempty"`
	Since string `json:"since"`
	Until string `json:"until"`
	Hash  string `json:"hash"`
}

func (c cursor) encode() string {
	data, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeCursor(text string) (cursor, error) {
	var c cursor
	data, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return c, errors.New("cursor is not base64url")
	}
	if err := json.Unmarshal(data, &c); err != nil || c.V != 1 {
		return c, errors.New("cursor is not a log_query cursor")
	}
	return c, nil
}

func (c cursor) times() (at, since, until time.Time, err error) {
	if at, err = time.Parse(time.RFC3339Nano, c.Time); err != nil {
		return
	}
	if since, err = time.Parse(time.RFC3339Nano, c.Since); err != nil {
		return
	}
	until, err = time.Parse(time.RFC3339Nano, c.Until)
	return
}

// paramsHash covers every request parameter except the cursor.
func paramsHash(p Params) string {
	p.Cursor = ""
	data, _ := json.Marshal(p)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}
