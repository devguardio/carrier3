package main

import (
    "github.com/spf13/cobra"
    "github.com/devguardio/carrier3/surface"
    "io/ioutil"
    "os"
    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    "github.com/go-chi/render"
    ik "github.com/devguardio/identity/go"
    "net/http"
    "context"
    "github.com/devguardio/carrier3"
    "time"
    "strings"
)


func main() {

    var rootCmd = &cobra.Command {
        Use:        "carrier3",
        Short:      "iot transport",
    }


    rootCmd.AddCommand(SurfaceCmd())

    var arg_disable_pty bool
    var arg_force_pty  bool
    shellCmd := &cobra.Command{
        Use:        "shell <identity> [cmd]",
        Short:      "connect to shell",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {

            // this is not how ssh behaves, which people expect i guess
            //c  := ""
            //for _, arg := range args[1:] {
            //  c += "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "' "
            //}
            c := strings.Join(args[1:], " ")
            code := shellMain(args[0], c, arg_disable_pty, arg_force_pty)
            os.Exit(code)
        },
    }
    shellCmd.Flags().BoolVarP(&arg_disable_pty, "disable-pty",  "T", false, "Disable pseudo-terminal allocation")
    shellCmd.Flags().BoolVarP(&arg_force_pty, "force-pty",  "t", false, "Request pseudo-terminal allocation, even if stdio is not a terminal")
    rootCmd.AddCommand(shellCmd)

    rootCmd.AddCommand(&cobra.Command{
        Use:        "publish <surface>",
        Short:      "a demo publisher",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {

            vault := ik.Vault();

            f, err := ioutil.ReadFile(args[0])
            if err != nil { panic(err) }

            sf, err := surface.Parse(f);
            if err != nil { panic(err) }

            r := chi.NewRouter()
            r.Use(middleware.Logger)
            r.Get("/", func(w http.ResponseWriter, r *http.Request) {
                render.JSON(w, r, map[string]string{
                    "hello": r.RemoteAddr,
                })
            })
            r.Handle("/v1/shell", carrier3.NewShellHandler("/bin/bash"))
            r.Handle("/demo/tick", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(200)
                for ;; {
                    w.Write([]byte("tick\r\n"))
                    if f, ok := w.(http.Flusher); ok {
                        f.Flush()
                    }
                    select {
                        case <- time.After(time.Second):
                        case <- r.Context().Done():
                            return
                    }
                }
            }))


            link, err := carrier3.Link(context.Background(), vault, sf);
            if err != nil { panic(err) }
            defer link.Close();

            server := &http.Server{
                Handler: r,
            }
            err = server.Serve(link);
            if err != nil { panic(err) }

        },
    })
    if err := rootCmd.Execute(); err != nil {
        os.Exit(1);
    }
}




