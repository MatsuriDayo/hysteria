//go:build !linux

package ssprotect

import (
	"net"
)

func Protect(c net.Conn, unixPath string) error {
	return nil
}
