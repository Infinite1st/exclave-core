package singbridge

import (
	"reflect"
	"syscall"
	"testing"

	"github.com/sagernet/sing/common/network"
)

func TestMethodImplementation(t *testing.T) {
	var c1 *noSyscallConn
	if reflect.TypeOf(c1).Implements(reflect.TypeFor[syscall.Conn]()) {
		t.Error("noSyscallConn must not implement syscall.Conn")
	}
	var c2 *quicCapableConn
	if reflect.TypeOf(c2).Implements(reflect.TypeFor[network.ReadCounter]()) {
		t.Error("quicCapableConn must not implement network.ReadCounter")
	}
	if reflect.TypeOf(c2).Implements(reflect.TypeFor[network.WriteCounter]()) {
		t.Error("quicCapableConn must not implement network.WriteCounter")
	}
	if reflect.TypeOf(c2).Implements(reflect.TypeFor[network.ReaderWithUpstream]()) {
		t.Error("quicCapableConn must not implement network.ReaderWithUpstream")
	}
	if reflect.TypeOf(c2).Implements(reflect.TypeFor[network.WriterWithUpstream]()) {
		t.Error("quicCapableConn must not implement network.WriterWithUpstream")
	}
}
