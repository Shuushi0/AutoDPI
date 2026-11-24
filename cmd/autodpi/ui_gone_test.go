package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/ipc"
)

// The page opened for a trial run ends with the service, and only then.
func TestServiceGone(t *testing.T) {
	down := &ipc.CallError{Kind: ipc.KindDown, Msg: "not running"}
	busy := &ipc.CallError{Kind: ipc.KindBusy, Msg: "busy"}
	run := func(answers []error, last error) (gone bool, calls int) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		gone = serviceGone(ctx, func() error {
			calls++
			if calls <= len(answers) {
				return answers[calls-1]
			}
			return last
		}, time.Millisecond)
		return
	}
	// It answered, then stopped: gone after three looks in a row.
	if gone, calls := run([]error{nil, nil}, down); !gone || calls != 5 {
		t.Errorf("answered then down: gone=%v after %d calls", gone, calls)
	}
	// Starting takes a few seconds: "not running" at first is no reason to go.
	if gone, _ := run([]error{down, down, down, down, nil, nil, down, nil}, nil); gone {
		t.Error("gone although the service came up and stayed")
	}
	// Busy, refused, or an error in its answer: it is there.
	if gone, _ := run([]error{nil}, busy); gone {
		t.Error("a busy service counted as gone")
	}
	if gone, _ := run([]error{nil}, errors.New("unknown command")); gone {
		t.Error("an answer that is an error counted as gone")
	}
	// It never comes up at all: gone after the wait for a start.
	if gone, _ := run(nil, down); !gone {
		t.Error("a service that never started was waited for without end")
	}
}
