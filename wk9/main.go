package wk9

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/Terry-Mao/goim/pkg/bufio"
)

const (
	// Frame header byte 0 bits from Section 5.2 of RFC 6455
	finBit  = 1 << 7
	rsv1Bit = 1 << 6
	rsv2Bit = 1 << 5
	rsv3Bit = 1 << 4
	opCode  = 0x0f

	// Frame header byte 1 bits from Section 5.2 of RFC 6455
	maskBit = 1 << 7
	lenBit  = 0x7f

	continuationFrame        = 0
	continuationFrameMaxRead = 100
)

// The frame types are defined in RFC 6455, section 11.8.
const (
	// ContinueFrame indicates this frame is a continued one.
	ContinueFrame = 0

	// TextFrame denotes a text data message. The text message payload is
	// interpreted as UTF-8 encoded text data.
	TextFrame = 1

	// BinaryFrame denotes a binary data message.
	BinaryFrame = 2

	// CloseFrame denotes a close control message. The optional message
	// payload contains a numeric code and text. Use the FormatCloseMessage
	// function to format a close message payload.
	CloseFrame = 8

	// PingFrame denotes a ping control message. The optional message payload
	// is UTF-8 encoded text.
	PingFrame = 9

	// PongFrame denotes a ping control message. The optional message payload
	// is UTF-8 encoded text.
	PongFrame = 10

	// All others are reserved frames.
)

var (
	// ErrMessageClose close control message
	ErrMessageClose = errors.New("close control message")
	// ErrMessageMaxRead continuation frame max read
	ErrMessageMaxRead = errors.New("continuation frame max read")
)

// Conn represents a WebSocket connection.
type Conn struct {
	rwc     io.ReadWriteCloser
	rdr     *bufio.Reader
	wtr     *bufio.Writer
	maskKey []byte
}

// new connection
func newConn(rwc io.ReadWriteCloser, r *bufio.Reader, w *bufio.Writer) *Conn {
	return &Conn{rwc: rwc, rdr: r, wtr: w, maskKey: make([]byte, 4)}
}

// ReadMessage read a message.
func (c *Conn) ReadMessage() (op int, payload []byte, err error) {
	var (
		fin         bool
		finOp, n    int
		partPayload []byte
	)
	for {
		// read frame
		if fin, op, partPayload, err = c.decodeFrame(); err != nil {
			return
		}
		switch op {
		case BinaryFrame, TextFrame, continuationFrame:
			if fin && len(payload) == 0 {
				return op, partPayload, nil
			}
			// continuation frame
			payload = append(payload, partPayload...)
			if op != continuationFrame {
				finOp = op
			}
			// final frame
			if fin {
				op = finOp
				return
			}
		case PingFrame:
			// handler ping
		case PongFrame:
			// handler pong
		case CloseFrame:
			// handler close
			err = ErrMessageClose
			return
		default:
			err = fmt.Errorf("unknown control message, fin=%t, op=%d", fin, op)
			return
		}
		if n > continuationFrameMaxRead {
			err = ErrMessageMaxRead
			return
		}
		n++
	}
}

func (c *Conn) decodeFrame() (bool, int, []byte, error) {
	var (
		b          byte
		s          []byte
		mask       bool
		maskKey    []byte
		payloadLen int64
		fin        bool
		op         int
		payload    []byte
		err        error
	)
	// 1.First byte. FIN/RSV1/RSV2/RSV3/OpCode(4bits)
	b, err = c.rdr.ReadByte()
	if err != nil {
		return fin, op, payload, err
	}
	// final frame
	fin = (b & finBit) != 0

	// rsv MUST be 0
	if rsv := b & (rsv1Bit | rsv2Bit | rsv3Bit); rsv != 0 {
		err = fmt.Errorf("unexpected reserved bits rsv1=%d, rsv2=%d, rsv3=%d", b&rsv1Bit, b&rsv2Bit, b&rsv3Bit)
		fmt.Printf("%s", err)
		return false, 0, nil, err
	}

	// op code
	op = int(b & opCode)

	// 2.Second byte. Mask/Payload len(7bits)
	b, err = c.rdr.ReadByte()
	if err != nil {
		return fin, op, nil, err
	}
	// is mask payload
	mask = (b & maskBit) != 0
	// payload length
	switch b & lenBit {
	case 126:
		// 16 bits
		if s, err = c.rdr.Pop(2); err != nil {
			return fin, op, nil, err
		}
		payloadLen = int64(binary.BigEndian.Uint16(s))
	case 127:
		// 64 bits
		if s, err = c.rdr.Pop(8); err != nil {
			return fin, op, nil, err
		}
		payloadLen = int64(binary.BigEndian.Uint64(s))
	default:
		// 7 bits
		payloadLen = int64(b & lenBit)
	}

	// read mask key
	if mask {
		maskKey, err = c.rdr.Pop(4)
		if err != nil {
			return fin, op, nil, err
		}
		if c.maskKey == nil {
			c.maskKey = make([]byte, 4)
		}
		copy(c.maskKey, maskKey)
	}
	// read payload
	if payloadLen > 0 {
		if payload, err = c.rdr.Pop(int(payloadLen)); err != nil {
			return fin, op, nil, err
		}
		if mask {
			maskBytes(c.maskKey, 0, payload)
		}
	}
	return fin, op, nil, err
}

func maskBytes(key []byte, pos int, b []byte) int {
	for i := range b {
		b[i] ^= key[pos&3]
		pos++
	}
	return pos & 3
}
