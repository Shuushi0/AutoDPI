//go:build !darwin && !windows

package netx

import (
	"context"
	"errors"
)

func watchRoutes(context.Context, func()) error {
	return errors.New("route notifications not implemented on this platform")
}
