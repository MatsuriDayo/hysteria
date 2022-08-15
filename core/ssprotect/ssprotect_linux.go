package ssprotect

import (
	"fmt"
	"net"
	"reflect"
	"syscall"
)

// GetFdFromConn get net.Conn's file descriptor.
func GetFdFromConn(l net.Conn) int {
	v := reflect.ValueOf(l)
	netFD := reflect.Indirect(reflect.Indirect(v).FieldByName("fd"))
	pfd := reflect.Indirect(netFD.FieldByName("pfd"))
	fd := int(pfd.FieldByName("Sysfd").Int())
	return fd
}

func Protect(c net.Conn, unixPath string) error {
	if c == nil {
		return nil
	}

	fd := GetFdFromConn(c)
	if fd == 0 {
		return nil
	}

	socket, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(socket)

	syscall.SetsockoptTimeval(socket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 3})
	syscall.SetsockoptTimeval(socket, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &syscall.Timeval{Sec: 3})

	err = syscall.Connect(socket, &syscall.SockaddrUnix{Name: unixPath})
	if err != nil {
		return err
	}

	err = syscall.Sendmsg(socket, nil, syscall.UnixRights(fd), nil, 0)
	if err != nil {
		return err
	}

	dummy := []byte{1}
	n, err := syscall.Read(socket, dummy)
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("protect failed")
	}
	return nil
}
