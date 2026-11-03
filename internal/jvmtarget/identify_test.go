package jvmtarget

import (
	"errors"
	"os"
	"testing"
)

func TestIdentifyReturnsTheProcessWithTheRecordedStartTime(t *testing.T) {
	h := newHost(t)
	h.addProcess(process{pid: 4242, nspid: []int{4242, 7}, start: 777})
	j, err := h.resolver().Identify(4242, 777)
	if err != nil {
		t.Fatal(err)
	}
	if j.PID != 4242 || j.NSPid != 7 || j.StartTime != 777 || j.EUID != uint32(os.Getuid()) {
		t.Errorf("jvm = %+v", j)
	}
}

func TestIdentifyRejectsAReusedPid(t *testing.T) {
	h := newHost(t)
	h.addProcess(process{pid: 4242, start: 778})
	if _, err := h.resolver().Identify(4242, 777); !errors.Is(err, ErrProcessChanged) {
		t.Errorf("start time differs: err = %v, want ErrProcessChanged", err)
	}
}

func TestIdentifyRejectsAMissingProcess(t *testing.T) {
	h := newHost(t)
	if _, err := h.resolver().Identify(4242, 777); !errors.Is(err, ErrProcessChanged) {
		t.Errorf("no process: err = %v, want ErrProcessChanged", err)
	}
	if _, err := h.resolver().Identify(0, 777); err == nil {
		t.Error("pid 0 was accepted")
	}
}
