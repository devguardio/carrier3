package carrier3

import (
    log     "github.com/sirupsen/logrus"
    "github.com/go-chi/render"
    "net/http"
    "io"
    "os/exec"
    "github.com/creack/pty"
    "encoding/binary"
    "os"
    "sync"
)

var ShellFrameTypeStdin   uint8  = 1
var ShellFrameTypeStdout  uint8  = 2
var ShellFrameTypeStderr  uint8  = 3
var ShellFrameTypePing    uint8  = 66
var ShellFrameTypeWinch   uint8  = 81
var ShellFrameTypeExit    uint8  = 82

func NewShellHandler(defaultshell string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {

    log.Println("shell handler start");
    defer log.Println("shell handler end");

    var wantPty = false
    var wantMux = false
    var args = []string{}
    var env  = []string{}

    for k,v := range r.Header {
        if len(v) == 0 {continue}
        if k == "Command" {
            args = append(args, "-c", v[0])
        } else if k == "Pty" {
            wantPty = true
        } else if k == "Mux" {
            wantMux = true
        } else if k == "Env" {
            //this would be dangerous if you have restricted users, but the usecase of carrier already assumes you want full yolo root
            env = append(env, v...)
        }
    }

    shell := exec.Command(defaultshell, args...)
    shell.Env = env

    dirname, _ := os.UserHomeDir()
    if dirname != "" {
        shell.Env = append(shell.Env, "HOME=" + dirname)
    }


    var ptmx        *os.File
    var procStdin   io.WriteCloser
    var procStdout  io.ReadCloser
    var procStderr  io.ReadCloser

    if wantPty {

        var err error
        ptmx, err = pty.Start(shell)
        if err != nil {
            w.WriteHeader(http.StatusInternalServerError)
            render.JSON(w, r, map[string]string{
                "error": err.Error(),
            })
            return;
        }

        procStdin  = ptmx
        procStdout = ptmx

    } else {

        stdin, err := shell.StdinPipe()
        if err != nil {
            render.JSON(w, r, map[string]string{
                "error": err.Error(),
            })
            return;
        }
        stdout, err := shell.StdoutPipe()
        if err != nil {
            render.JSON(w, r, map[string]string{
                "error": err.Error(),
            })
            return;
        }
        stderr, err := shell.StderrPipe()
        if err != nil {
            render.JSON(w, r, map[string]string{
                "error": err.Error(),
            })
            return;
        }

        err = shell.Start();
        if err != nil {
            stdin.Close();
            stdout.Close();
            stderr.Close();

            w.WriteHeader(http.StatusInternalServerError)
            render.JSON(w, r, map[string]string{
                "error": err.Error(),
            })
            return;
        }

        procStdin  = stdin
        procStdout = stdout
        procStderr = stderr

    }

    var R io.Reader
    var W io.WriteCloser

    var unwindOnce sync.Once
    var unwind = func() {
        unwindOnce.Do(func() {
            log.Println("closing shell");
            procStdin.Close()
            procStdout.Close()
            if procStderr != nil {
                procStderr.Close();
            }
            shell.Process.Kill()
            sta, _ := shell.Process.Wait()
            var exitCode int = 666;
            if sta != nil {
                exitCode = sta.ExitCode()
            }
            if wantMux {
                b := []byte{ShellFrameTypeExit, 0, 1, 0, uint8(exitCode)}
                W.Write(b[:])
            }
        })
    }
    defer unwind();

    con, _, err := w.(http.Hijacker).Hijack()
    if err != nil { panic(err) }
    defer con.Close();



    os.Stderr.Write([]byte("REQ HEADERS=>\n"))
    r.Header.Write(os.Stderr)

    if r.Header.Get("Connection") == "Upgrade" {
        con.Write([]byte("HTTP/1.1 101 Upgrade\r\nUpgrade: shell\r\n\r\n"))
    } else {
        con.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
    }

    R = io.Reader(con)
    W = io.WriteCloser(con)

    chunkedIn := false
    if r.Header.Get("Transfer-Encoding") == "chunked" {
        chunkedIn = true
    }
    for _,v := range r.TransferEncoding {
        if v == "chunked" {
            chunkedIn = true
        }
    }
    if chunkedIn {
        R = NewChunkedReader(R)
    }

    if !wantMux {
        if procStderr != nil {
            go func() {
                defer con.Close();
                io.Copy(W, procStderr)
            }()
        }
        go func() {
            defer con.Close();
            io.Copy(W, procStdout)
        }()
        io.Copy(procStdin, R)
        return
    }

    // TODO golang won't respond if there's no body yet. this breaks with !wantMux above
    W.Write([]byte{ShellFrameTypePing, 0, 0, 0})

    go func() {
        defer W.Close();
        defer unwind();

        var b [1000]byte
        for {
            n, err := procStdout.Read(b[4:])
            if err != nil || n == 0 {
                break
            }
            b[0] = ShellFrameTypeStdout
            b[1] = 0
            binary.LittleEndian.PutUint16(b[2:], uint16(n))
            W.Write(b[:4+n])
        }
    }()

    if procStderr != nil {
        go func() {
            defer W.Close();
            defer unwind();

            var b [1000]byte
            for {
                n, err := procStderr.Read(b[4:])
                if err != nil || n == 0 {
                    break
                }
                b[0] = ShellFrameTypeStderr
                b[1] = 0
                binary.LittleEndian.PutUint16(b[2:], uint16(n))
                W.Write(b[:4+n])
            }
        }()
    }

    var b [1000]byte
    for {

        var h [4]byte
        n, err := io.ReadFull(R, h[:])
        if err != nil || n == 0 {
            if err != io.EOF {
                log.Warn(err)
            }
            break
        }
        l := binary.LittleEndian.Uint16(h[2:])

        log.Println(h)

        for ;; {
            var max = l
            if max > uint16(len(b)) {
                max = uint16(len(b))
            }
            n, err := io.ReadFull(R, b[:max])
            if err != nil {
                if err != io.EOF {
                    log.Warn(err)
                }
                break
            }

            switch h[0] {
                case ShellFrameTypeStdin, ShellFrameTypeStdout:
                    procStdin.Write(b[:n])
                    if n == 0 {
                        procStdin.Close()
                    }
                case ShellFrameTypeWinch:
                    var ws pty.Winsize
                    ws.Rows = binary.LittleEndian.Uint16(b[:])
                    ws.Cols = binary.LittleEndian.Uint16(b[2:])
                    ws.X    = binary.LittleEndian.Uint16(b[2+2:])
                    ws.Y    = binary.LittleEndian.Uint16(b[2+2+2:])
                    if ptmx != nil {
                        pty.Setsize(ptmx, &ws)
                    }
            }

            l -= uint16(n)
            if l < 1 {
                break
            }
        }

    }
}
}
