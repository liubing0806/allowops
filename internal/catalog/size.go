package catalog

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Size is always a byte count after YAML/JSON decoding. Builtin handler configs can reuse it (design P12).
type Size int64

var sizePattern = regexp.MustCompile(`(?i)^([0-9]+)(B|KB|MB|GB)?$`)

// ParseSize accepts nonnegative integer bytes or binary B/KB/MB/GB strings.
// Individual fields decide whether zero is allowed; max_output requires a positive value.
func ParseSize(value any) (int64, error) {
	var text string
	switch v := value.(type) {
	case Size:
		if v < 0 {
			return 0, fmt.Errorf("size must be nonnegative")
		}
		return int64(v), nil
	case int:
		text = strconv.FormatInt(int64(v), 10)
	case int64:
		text = strconv.FormatInt(v, 10)
	case uint64:
		text = strconv.FormatUint(v, 10)
	case json.Number:
		text = v.String()
	case string:
		text = v
	default:
		return 0, fmt.Errorf("size must be integer bytes or a B/KB/MB/GB string")
	}
	m := sizePattern.FindStringSubmatch(text)
	if m == nil {
		return 0, fmt.Errorf("invalid size; allowed: nonnegative integer bytes or B/KB/MB/GB")
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("size overflows int64")
	}
	multiplier := int64(1)
	switch strings.ToUpper(m[2]) {
	case "KB":
		multiplier = 1024
	case "MB":
		multiplier = 1024 * 1024
	case "GB":
		multiplier = 1024 * 1024 * 1024
	}
	if n > (1<<63-1)/multiplier {
		return 0, fmt.Errorf("size overflows int64")
	}
	return n * multiplier, nil
}

func (s *Size) UnmarshalYAML(node *yaml.Node) error {
	var value any
	if err := node.Decode(&value); err != nil {
		return err
	}
	n, err := ParseSize(value)
	if err != nil {
		return err
	}
	*s = Size(n)
	return nil
}

func (s *Size) UnmarshalJSON(data []byte) error {
	var value any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	n, err := ParseSize(value)
	if err != nil {
		return err
	}
	*s = Size(n)
	return nil
}
