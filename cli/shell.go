package cli

import (
    "crypto/tls"
    "crypto/x509"
    "encoding/binary"
    "fmt"
    "github.com/creack/pty"
    "github.com/devguardio/carrier3/v3"
    "golang.org/x/term"
    ik      "github.com/devguardio/identity/go"
    iktls   "github.com/devguardio/identity/go/tls"
    "io"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "golang.org/x/crypto/ssh/terminal"
    "bufio"
    "bytes"
)

func Shell(vault ik.VaultI, target string, cmd string, disable_pty bool, force_pty bool) (exitCode int) {

    requestPTY := terminal.IsTerminal(syscall.Stdin)
    if disable_pty {
        requestPTY = false
    } else if force_pty {
        requestPTY = true
    }
    var printHeaders = requestPTY;

    tlsconf, err := iktls.NewTlsClient(vault)
    if err != nil { panic(err) }
    tlsconf.RootCAs, _ = x509.SystemCertPool()
    tlsconf.ServerName = "carrier.devguard.io"

    conn, err := tls.Dial("tcp", "carrier.devguard.io:443", tlsconf)
    if err != nil { panic(err) }
    defer conn.Close();

    req, err := http.NewRequest("POST", "https://carrier.devguard.io/v1/shell", nil)
    if err != nil { panic(err) }

    req.Header.Add("Target",  target)
    req.Header.Add("Mux",     "true")
    if requestPTY {
        req.Header.Add("Pty", "true")
    }
    if cmd != "" {
        req.Header.Add("Command", cmd)
    }

    if os.Getenv("TERM") != "" {
        req.Header.Add("Env", "TERM=" + os.Getenv("TERM"))
    }

    // have to manually write the request because golang has some bad assumptions for request body
    rqb := bytes.Buffer{}
    req.Header.Add("Host", "carrier.devguard.io" )
    req.Header.Add("Connection", "close")
    req.Header.Add("Transfer-Encoding", "chunked")

    rqb.Write([]byte("POST /v1/shell HTTP/1.1\r\n"))
    req.Header.Write(&rqb)
    rqb.Write([]byte("\r\n"))

    conn.Write(rqb.Bytes())

    // read response
    resp, err := http.ReadResponse(bufio.NewReader(conn), req)
    if err != nil { panic(err) }

    if printHeaders {
        fmt.Fprintf(os.Stderr, "%s %s\n", resp.Proto, resp.Status);
        for k,v := range resp.Header {
            for _, v := range v {
                fmt.Fprintf(os.Stderr, "%s: %s\n", k, v);
            }
        }
        fmt.Fprintf(os.Stderr, "\n")
    }

    if resp.StatusCode >= 300 {
        if !printHeaders {
            fmt.Fprintf(os.Stderr, "%s %s\n", resp.Proto, resp.Status);
        }
        if resp.StatusCode != 503 {
            return 8888;
        }
        io.Copy(os.Stderr, resp.Body)
        os.Exit(resp.StatusCode)
        return
    }

    R := resp.Body
    W := carrier3.NewChunkedWriter(conn)

    // golang http client won't send the request if there's no start of body
    // W.Write([]byte{carrier3.ShellFrameTypePing, 0, 0, 0})

    if requestPTY {

        // Handle pty size.
        ch := make(chan os.Signal, 1)
        signal.Notify(ch, syscall.SIGWINCH)
        go func() {
            for range ch {
                var b = [4+8]byte{carrier3.ShellFrameTypeWinch, 0, 8, 0}
                ws, err := pty.GetsizeFull(os.Stdin)
                if err == nil {
                    binary.LittleEndian.PutUint16(b[4:],        ws.Rows)
                    binary.LittleEndian.PutUint16(b[4+2:],      ws.Cols)
                    binary.LittleEndian.PutUint16(b[4+2+2:],    ws.X)
                    binary.LittleEndian.PutUint16(b[4+2+2+2:],  ws.Y)

                    W.Write(b[:])
                }
            }
        }()
        ch <- syscall.SIGWINCH // Initial resize.
        defer func() { signal.Stop(ch); close(ch) }() // Cleanup signals when done.

        // Set stdin in raw mode.
        oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
        if err == nil {
            defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }() // Best effort.
        }

    }

    go func() {
        //defer W.Close();
        var b [1000]byte
        for {
            n, err := os.Stdin.Read(b[4:])

            b[0] = carrier3.ShellFrameTypeStdin
            b[1] = 0
            binary.LittleEndian.PutUint16(b[2:], uint16(n))
            W.Write(b[:4+n])

            if err != nil {
                if err != io.EOF {
                    fmt.Fprintln(os.Stderr, n, err)
                }
                break
            }
        }
    }()

    var b [1000]byte
    for {
        var h [4]byte
        n, err := io.ReadFull(R, h[:])
        if err != nil || n == 0 {
            break
        }
        l := binary.LittleEndian.Uint16(h[2:])

        for ;; {
            var max = l
            if max > uint16(len(b)) {
                max = uint16(len(b))
            }
            n, err := io.ReadFull(R, b[:max])
            if err != nil {
                break
            }

            switch h[0] {
                case carrier3.ShellFrameTypeStdin, carrier3.ShellFrameTypeStdout:
                    os.Stdout.Write(b[:n])
                case carrier3.ShellFrameTypeStderr:
                    os.Stderr.Write(b[:n])
                case carrier3.ShellFrameTypeExit:
                    exitCode = int(b[0])
            }

            l -= uint16(n)
            if l < 1 {
                break
            }
        }

    }

    return
}
