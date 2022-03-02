package carrier3


import (
    "github.com/devguardio/carrier3/v3/surface"
    ik  "github.com/devguardio/identity/go"
    log "github.com/sirupsen/logrus"
    "github.com/devguardio/carrier3/v3/api"

    "encoding/json"
    "context"
    "net"
    "io"
    "fmt"
    "bufio"
    "encoding/binary"
    "strings"
    "time"
)

func Link(ctx context.Context, vault ik.VaultI, sf *surface.Surface) (*H1Link, error) {
    return &H1Link {
        vault:  vault,
        sf:     sf,
        ctx:    ctx,
    }, nil
}

type H1Link struct {
    ctx     context.Context
    vault   ik.VaultI
    sf      *surface.Surface
}

func (self *H1Link) Close() error {
    return nil
}

func (self *H1Link) Addr() net.Addr {
    return nil
}

func (self *H1Link) acceptOnce() (net.Conn, error) {

    selfid, _ := self.vault.Identity();

    dialer := surface.NewDialer(self.vault, self.sf);
    conn, ingress, err := dialer.DialContext(self.ctx)
    if err != nil { return nil, err }

    conn.Write([]byte(fmt.Sprintf(
        "CONNECT /v1/listen HTTP/1.1\r\n"+
        "Upgrade: carrier3-cast\r\n"+
        "Connection: Upgrade\r\n"+
        "Host: %s\r\n\r\n", ingress.Name)))

    // read http1 upgrade response

    bio := bufio.NewReader(conn)
    line ,_, err := bio.ReadLine()
    if err != nil { conn.Close(); return nil, err }
    lines := strings.Split(string(line), " ")
    if len(lines) < 3 || lines[1] != "101" {
        return nil, fmt.Errorf("response: %s", line)
    }

    for ;; {
        line ,_, err := bio.ReadLine()
        if err != nil { conn.Close(); return nil, err }
        if len(line) == 0 { break }
        log.Println(string(line))
    }

    if bio.Buffered() != 0 {
        // can't be bothered to implement this. it propably never happens anyway
        return nil, fmt.Errorf("race. body after connect arrived too early")
    }

    // idle waiting for reverse conn
    log.Println("awaiting reverse connection");
    var b [1]byte
    for ;; {
        _ , err := conn.Read(b[:])
        if err != nil { conn.Close(); return nil, err }
        if b[0] == 0xff {
            var hl uint16
            err := binary.Read(conn, binary.LittleEndian, &hl)
            if err != nil { conn.Close(); return nil, fmt.Errorf("waiting for broker headers: %w", err) }

            var headerbytes = make([]byte, hl)
            _, err = io.ReadFull(conn, headerbytes)
            if err != nil { conn.Close(); return nil, fmt.Errorf("read broker headers: %w", err) }

            var brokerHeaders api.Connect
            err = json.Unmarshal(headerbytes, &brokerHeaders)
            if err != nil { conn.Close(); return nil, fmt.Errorf("parse broker headers: %w", err) }

            //TODO auth
            log.Println("accepting reverse connection from", brokerHeaders.Caller);
            caller, _  := ik.IdentityFromString(brokerHeaders.Caller)

            return &H1Stream{
                Conn:               conn,
                CallerIdentity:     caller,
                MyIdentity:         selfid,
            }, nil
        } else if b[0] == 0x01 {
            conn.Write([]byte{0x02})
        }
    }
}


func (self *H1Link) Accept() (net.Conn, error) {
    for ;; {
        c, err := self.acceptOnce()

        select {
            case <- self.ctx.Done():
                return nil, fmt.Errorf("canceled");
            default:
        }

        if err != nil {
            log.Error(err);
            time.Sleep(5 * time.Second);
            continue
        }
        return c, nil
    }
}

type GoNetCarrierAddr struct {id*ik.Identity}
func (self GoNetCarrierAddr) Network() string {return "carrier" }
func (self GoNetCarrierAddr) String() string  {
    if self.id == nil {
        return "<anon>"
    }
    return self.id.String()
}
type H1Stream struct {
    CallerIdentity  *ik.Identity
    MyIdentity      *ik.Identity
    Conn            net.Conn
}
func (self *H1Stream) Close() error {
    log.Println("H1 STREAM CLOSED")
    return self.Conn.Close();
}
func (self *H1Stream) SetDeadline(t time.Time) error {
    return self.Conn.SetDeadline(t)
}
func (self *H1Stream) SetReadDeadline(t time.Time) error {
    return self.Conn.SetReadDeadline(t)
}
func (self *H1Stream) SetWriteDeadline(t time.Time) error {
    return self.Conn.SetWriteDeadline(t)
}
func (self *H1Stream) Read(p []byte) (int, error) {
    return self.Conn.Read(p)
}
func (self *H1Stream) Write(p []byte) (int, error) {
    return self.Conn.Write(p)
}
func (self *H1Stream) RemoteAddr() net.Addr {
    return GoNetCarrierAddr{self.CallerIdentity}
}
func (self *H1Stream) LocalAddr() net.Addr {
    return GoNetCarrierAddr{self.MyIdentity}
}
