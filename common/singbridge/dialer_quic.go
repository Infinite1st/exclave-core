package singbridge

import (
	"io"
	"net"
	"syscall"

	"github.com/sagernet/sing/common/network"
	"golang.org/x/net/ipv4"

	"github.com/exclavenetwork/exclave-core/v5/features/stats"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

var (
	_ net.Conn             = (*noSyscallConn)(nil)
	_ net.Conn             = (*quicCapableConn)(nil)
	_ net.PacketConn       = (*quicCapableConn)(nil)
	_ syscall.Conn         = (*quicCapableConn)(nil)
	_ batchReader          = (*quicCapableConn)(nil)
	_ ioActivityFuncs      = (*quicCapableConn)(nil)
	_ network.ReadCounter  = (*quicCapableCounterConn)(nil)
	_ network.WriteCounter = (*quicCapableCounterConn)(nil)
)

// FIXME: add method for internet.Dialer to create a connect() socket instead of converting a bind() socket to a connect() socket
func NewQUICDialerWrapper(dialer internet.Dialer) *dialerWrapper {
	return &dialerWrapper{
		dialer: dialer,
		quic:   true,
	}
}

func newQUICConnectPacketConn(conn net.Conn) net.Conn {
	var readCounter, writeCounter stats.Counter
	iConn := conn
	if statConn, ok := iConn.(*internet.StatCouterConnection); ok {
		iConn = statConn.Connection
		readCounter = statConn.ReadCounter
		writeCounter = statConn.WriteCounter
	}
	var packetConn net.PacketConn
	switch iConn := iConn.(type) {
	case *internet.PacketConnWrapper:
		if _, ok := iConn.Conn.(syscall.Conn); !ok {
			return conn
		}
		packetConn = iConn.Conn
	case net.PacketConn:
		if _, ok := iConn.(syscall.Conn); !ok {
			return conn
		}
		packetConn = iConn
	default:
		if !supportOOB {
			return conn
		}
		if _, ok := conn.(syscall.Conn); !ok {
			return conn
		}
		return &noSyscallConn{Conn: conn}
	}
	syscallConn, err := packetConn.(syscall.Conn).SyscallConn()
	if err != nil {
		return &noSyscallConn{Conn: conn}
	}
	if supportOOB {
		// https://github.com/SagerNet/quic-go/blob/acafdc7599d1238495def470f7077b3212903b1f/sys_conn_oob.go#L496
		// connect() socket required
		addr, ok := conn.RemoteAddr().(*net.UDPAddr)
		if !ok {
			return &noSyscallConn{Conn: conn}
		}
		if err := connect(syscallConn, addr); err != nil {
			return &noSyscallConn{Conn: conn}
		}
	}
	quicCapableConn := &quicCapableConn{
		Conn:         conn,
		packetConn:   packetConn,
		syscallConn:  syscallConn,
		readCounter:  readCounter,
		writeCounter: writeCounter,
		onRead: func(size int) {
			if readCounter != nil {
				readCounter.Add(int64(size))
			}
		},
		onWrite: func(size int) {
			if writeCounter != nil {
				writeCounter.Add(int64(size))
			}
		},
	}
	if batchReader, ok := packetConn.(batchReader); ok {
		quicCapableConn.readBatch = batchReader.ReadBatch
	} else {
		quicCapableConn.readBatch = ipv4.NewPacketConn(quicCapableConn).ReadBatch
	}
	return &quicCapableCounterConn{
		quicCapableConn: quicCapableConn,
	}
}

// noSyscallConn must NOT implement syscall.Conn
type noSyscallConn struct {
	net.Conn
}

type quicCapableConn struct {
	net.Conn
	packetConn   net.PacketConn
	syscallConn  syscall.RawConn
	readBatch    func(ms []ipv4.Message, flags int) (int, error)
	readCounter  stats.Counter
	writeCounter stats.Counter
	onRead       func(size int)
	onWrite      func(size int)
}

func (c *quicCapableConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.packetConn.ReadFrom(p)
	c.onRead(n)
	return n, addr, err
}

func (c *quicCapableConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.packetConn.WriteTo(p, addr)
	c.onWrite(n)
	return n, err
}

// https://github.com/SagerNet/quic-go/blob/acafdc7599d1238495def470f7077b3212903b1f/sys_conn.go#L54
// https://github.com/SagerNet/quic-go/blob/acafdc7599d1238495def470f7077b3212903b1f/sys_conn.go#L90
func (c *quicCapableConn) SyscallConn() (syscall.RawConn, error) {
	return c.syscallConn, nil
}

type batchReader interface {
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
}

// https://github.com/SagerNet/quic-go/blob/acafdc7599d1238495def470f7077b3212903b1f/sys_conn_oob.go#L243-L250
// https://github.com/SagerNet/quic-go/blob/acafdc7599d1238495def470f7077b3212903b1f/sys_conn_oob.go#L309-L316
func (c *quicCapableConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	// onRead is used
	// https://github.com/SagerNet/quic-go/blob/eb58c34e762a0fe39f6f4c1fac9aa17e98236915/sys_conn_oob.go#L380-L386
	return c.readBatch(ms, flags)
}

type ioActivityFuncs interface {
	IOActivityFuncs() (func(size int), func(size int))
}

// https://github.com/SagerNet/quic-go/blob/eb58c34e762a0fe39f6f4c1fac9aa17e98236915/sys_conn_oob.go#L277
// https://github.com/SagerNet/quic-go/blob/eb58c34e762a0fe39f6f4c1fac9aa17e98236915/sys_conn_oob.go#L348
func (c *quicCapableConn) IOActivityFuncs() (func(size int), func(size int)) {
	return c.onRead, c.onWrite
}

type quicCapableCounterConn struct {
	*quicCapableConn
}

// https://github.com/SagerNet/sing-quic/blob/06fb2e6b0c958aece20bd601ca42167c932673a2/quic.go#L127
// https://github.com/SagerNet/sing/blob/3f8f790b7a2968307bbf900544fc8030791c715e/common/network/counter.go#L33
func (c *quicCapableCounterConn) UnwrapReader() (io.Reader, []network.CountFunc) {
	return c.quicCapableConn, []network.CountFunc{func(n int64) {
		if c.readCounter != nil {
			c.readCounter.Add(n)
		}
	}}
}

// https://github.com/SagerNet/sing-quic/blob/06fb2e6b0c958aece20bd601ca42167c932673a2/quic.go#L132
// https://github.com/SagerNet/sing/blob/3f8f790b7a2968307bbf900544fc8030791c715e/common/network/counter.go#L54
func (c *quicCapableCounterConn) UnwrapWriter() (io.Writer, []network.CountFunc) {
	return c.quicCapableConn, []network.CountFunc{func(n int64) {
		if c.writeCounter != nil {
			c.writeCounter.Add(n)
		}
	}}
}
