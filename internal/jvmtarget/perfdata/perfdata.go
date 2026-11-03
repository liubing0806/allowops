// Package perfdata parses HotSpot hsperfdata files (the PerfData memory
// region that jstat and jps read). Parsing needs no attach and sends no signal.
//
// The layout is the one of PerfDataPrologue and PerfDataEntry in HotSpot's
// perfMemory.hpp, which JDK 8 to 21 all write as format 2.0:
//
//	prologue, 32 bytes: magic 0xcafec0c0 (always big endian), byte order (0 big,
//	1 little), major, minor, accessible, used (int), overflow (int), mod time
//	(long), entry offset (int), entry count (int)
//	entry, 20 bytes + name + data: length, name offset, vector length (ints), data
//	type, flags, units, variability (bytes), data offset (int)
//
// Every length and offset is checked against the file before it is used.
package perfdata

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// MaxFileSize bounds the size of a file Parse and its callers accept. The
// default PerfDataMemorySize is 32KiB.
const MaxFileSize = 16 << 20

const (
	prologueSize = 32
	entryHeader  = 20
	magic        = 0xcafec0c0
	// maxNameLen bounds counter names; HotSpot's longest are about 100 bytes.
	maxNameLen = 256
)

var (
	// ErrNotPerfData means the magic number does not match.
	ErrNotPerfData = errors.New("not a HotSpot hsperfdata file")
	// ErrUnsupported means the file has a version or byte order this parser does not know.
	ErrUnsupported = errors.New("unsupported hsperfdata version or byte order")
	// ErrNotReady means the JVM has not marked the region accessible yet.
	ErrNotReady = errors.New("hsperfdata is not accessible yet")
	// ErrCorrupt means a length or offset lies outside the file.
	ErrCorrupt = errors.New("corrupt hsperfdata")
	// ErrIncomplete means the file is well formed but lacks the counters every
	// supported JVM publishes.
	ErrIncomplete = errors.New("hsperfdata lacks the expected JVM counters")
)

// Kind tells whether an Entry holds a number or a string.
type Kind uint8

const (
	KindLong Kind = iota + 1
	KindText
)

// Entry is one counter.
type Entry struct {
	Name        string
	Kind        Kind
	Long        int64
	Text        string
	Units       uint8
	Variability uint8
}

// PerfData is a parsed hsperfdata file. Entries may hold values that must not
// be shown to callers (sun.rt.javaCommand, java.rt.vmArgs, java.rt.vmFlags and
// system properties); String therefore never prints them.
type PerfData struct {
	Major, Minor uint8
	BigEndian    bool
	Entries      map[string]Entry
}

func corrupt(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, args...))
}

// Parse validates and decodes one hsperfdata file.
//
// The JVM keeps appending entries while it runs, so entries beyond the count
// in the prologue are ignored, and so are entries of a type other than long
// scalar and byte vector (string). When a name appears twice the first wins.
func Parse(data []byte) (*PerfData, error) {
	if len(data) > MaxFileSize {
		return nil, corrupt("file is larger than %d bytes", MaxFileSize)
	}
	if len(data) < 4 || binary.BigEndian.Uint32(data) != magic {
		return nil, ErrNotPerfData
	}
	if len(data) < prologueSize {
		return nil, corrupt("file is shorter than the %d byte prologue", prologueSize)
	}
	p := &PerfData{Major: data[5], Minor: data[6], Entries: make(map[string]Entry)}
	var order binary.ByteOrder
	switch data[4] {
	case 0:
		order, p.BigEndian = binary.BigEndian, true
	case 1:
		order = binary.LittleEndian
	default:
		return nil, fmt.Errorf("%w: byte order %d", ErrUnsupported, data[4])
	}
	if p.Major != 2 {
		return nil, fmt.Errorf("%w: version %d.%d", ErrUnsupported, p.Major, p.Minor)
	}
	if data[7] == 0 {
		return nil, ErrNotReady
	}
	used := int64(int32(order.Uint32(data[8:])))
	offset := int64(int32(order.Uint32(data[24:])))
	count := int64(int32(order.Uint32(data[28:])))
	if used < prologueSize || used > int64(len(data)) {
		return nil, corrupt("used size %d outside the %d byte file", used, len(data))
	}
	if offset < prologueSize || offset > used {
		return nil, corrupt("entry offset %d outside the used area", offset)
	}
	// An entry takes at least its header, which bounds the count.
	if count < 0 || count > (used-offset)/entryHeader {
		return nil, corrupt("entry count %d does not fit the used area", count)
	}
	area := data[:used]
	for i := int64(0); i < count; i++ {
		length, err := parseEntry(p, order, area, offset)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		offset += length
	}
	return p, nil
}

// parseEntry decodes the entry at offset and returns its length.
func parseEntry(p *PerfData, order binary.ByteOrder, area []byte, offset int64) (int64, error) {
	if offset+entryHeader > int64(len(area)) {
		return 0, corrupt("header beyond the used area")
	}
	h := area[offset : offset+entryHeader]
	length := int64(int32(order.Uint32(h)))
	nameOffset := int64(int32(order.Uint32(h[4:])))
	vectorLength := int64(int32(order.Uint32(h[8:])))
	dataType, units, variability := h[12], h[14], h[15]
	dataOffset := int64(int32(order.Uint32(h[16:])))
	if length < entryHeader || length > int64(len(area))-offset {
		return 0, corrupt("length %d outside the used area", length)
	}
	entry := area[offset : offset+length]
	if nameOffset < entryHeader || nameOffset >= length {
		return 0, corrupt("name offset %d outside the entry", nameOffset)
	}
	end := nameOffset
	for end < length && entry[end] != 0 {
		end++
	}
	name := entry[nameOffset:end]
	if end == length || len(name) == 0 || len(name) > maxNameLen {
		return 0, corrupt("name is empty, too long or not terminated")
	}
	for _, c := range name {
		if c < 0x20 || c > 0x7e {
			return 0, corrupt("name has a byte outside printable ASCII")
		}
	}
	if dataOffset < entryHeader || dataOffset > length {
		return 0, corrupt("data offset %d outside the entry", dataOffset)
	}
	if vectorLength < 0 {
		return 0, corrupt("negative vector length")
	}
	e := Entry{Name: string(name), Units: units, Variability: variability}
	switch {
	case dataType == 'J' && vectorLength == 0:
		if length-dataOffset < 8 {
			return 0, corrupt("long value does not fit the entry")
		}
		e.Kind, e.Long = KindLong, int64(order.Uint64(entry[dataOffset:]))
	case dataType == 'J':
		return 0, corrupt("long counter with a vector length")
	case dataType == 'B' && vectorLength > 0:
		if vectorLength > length-dataOffset {
			return 0, corrupt("string of %d bytes does not fit the entry", vectorLength)
		}
		raw := entry[dataOffset : dataOffset+vectorLength]
		if i := bytes.IndexByte(raw, 0); i >= 0 {
			raw = raw[:i]
		}
		e.Kind, e.Text = KindText, string(raw)
	default:
		// Other element types are not published by the supported JVMs.
		return length, nil
	}
	if _, seen := p.Entries[e.Name]; !seen {
		p.Entries[e.Name] = e
	}
	return length, nil
}

// Long returns the numeric counter with the given name.
func (p *PerfData) Long(name string) (int64, bool) {
	e, ok := p.Entries[name]
	return e.Long, ok && e.Kind == KindLong
}

// Text returns the string counter with the given name.
func (p *PerfData) Text(name string) (string, bool) {
	e, ok := p.Entries[name]
	return e.Text, ok && e.Kind == KindText
}

// String describes the file without any counter value.
func (p *PerfData) String() string {
	if p == nil {
		return "hsperfdata(nil)"
	}
	return fmt.Sprintf("hsperfdata(format %d.%d, %d counters)", p.Major, p.Minor, len(p.Entries))
}

// FirstWord returns the part of a sun.rt.javaCommand value before the first
// space: the main class, or the jar path of a -jar launch. The arguments after
// it can hold secrets and must not be kept.
func FirstWord(command string) string {
	first, _, _ := strings.Cut(command, " ")
	return first
}
