// https://github.com/projectdiscovery/httpx/blob/master/common/httpx/encodings.go
package shell

import (
	"bytes"
	"io/ioutil"
	"net"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// Credits: https://gist.github.com/zhangbaohe/c691e1da5bbdc7f41ca5

// DecodeGbk converts GBK to UTF-8
func DecodeGbk(s []byte) []byte {
	I := bytes.NewReader(s)
	O := transform.NewReader(I, simplifiedchinese.GBK.NewDecoder())
	d, e := ioutil.ReadAll(O)
	if e != nil {
		return s
	}
	return d
}

type WindowsConn struct {
	net.Conn
}

func (wc *WindowsConn) Write(b []byte) (n int, err error) {
	n = len(b)
	_, err = wc.Conn.Write(DecodeGbk(b))
	return
}

func (wc *WindowsConn) Read(b []byte) (n int, err error) {
	return wc.Conn.Read(b)
}

func NewWindowsConn(conn net.Conn) *WindowsConn {
	return &WindowsConn{conn}
}
