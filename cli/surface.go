package main

import (
    "github.com/devguardio/identity/go"
    "github.com/spf13/cobra"
    "github.com/devguardio/carrier3/surface"
    "io/ioutil"
    "encoding/json"
    "os"
    "time"
    "fmt"
    "net"
    "encoding/pem"
    "crypto/x509"
)


func SurfaceCmd() * cobra.Command {

    var rootCmd = &cobra.Command {
        Use:        "surface",
        Short:      "signed surface documents",
    }

    var sf surface.Surface

    var arg_identity    [16]string
    var arg_ips         [16][]string
    var arg_cert_file   [16][]string

    makeCmd := &cobra.Command{
        Use:        "make <outfile>",
        Short:      "create surface",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {

            secret, err := identity.CreateSecret();
            if err != nil { panic(err) }

            id, err := secret.Identity()
            if err != nil { panic(err) }
            copy(sf.Sequencer[:], id[:])

            outfile, err := os.Create(args[0])
            if err != nil { panic(err) }

            sf.Time = time.Now();

            for i := 0; i < 16; i++ {
                if arg_identity[i] != "" {
                    id, err := identity.IdentityFromString(arg_identity[i])
                    if err != nil { panic(fmt.Errorf("identity%d: %w", i, err)) }

                    sf.Ingresses[i].Identity = id
                }


                for _, ips := range arg_ips[i] {
                    ip := net.ParseIP(ips)
                    if ip == nil {panic(fmt.Errorf("ip%d: cannot parse", i))}
                    sf.Ingresses[i].IP = append(sf.Ingresses[i].IP, ip)
                }

                for _, certfile := range arg_cert_file[i] {
                    p, err := ioutil.ReadFile(certfile)
                    block, _ := pem.Decode([]byte(p))
                    if block == nil { panic(fmt.Errorf("cert-file%d: cannot parse pem", i))}
                    cert, err := x509.ParseCertificate(block.Bytes)
                    if err != nil { panic(fmt.Errorf("cert-file%d: cannot parse cert: %w", i, err))}
                    sf.Ingresses[i].Certs = append(sf.Ingresses[i].Certs, cert)
                }

            }

            if sf.Precedent >= sf.Serial {
                panic("precedent must be < serial")
            }

            b := sf.Serialize()
            outfile.Write(b)

            outfileSecret, err := os.Create(args[0] + ".secret")
            if err != nil { panic(err) }
            outfileSecret.Write([]byte(secret.ToString()))
        },
    }
    makeCmd.Flags().Uint64Var((*uint64)(&sf.Serial), "serial",  0, "serial nr")
    makeCmd.MarkFlagRequired("serial");

    makeCmd.Flags().Uint64Var((*uint64)(&sf.Precedent), "precedent",  0, "precedent nr")
    makeCmd.MarkFlagRequired("precedent");

    for i := 0; i < 16; i++ {
        makeCmd.Flags().StringVar(&sf.Ingresses[i].Name, fmt.Sprintf("name%d",i),  "", fmt.Sprintf("domain name (%d)", i))
        makeCmd.Flags().StringVar(&arg_identity[i], fmt.Sprintf("identity%d",i),  "", fmt.Sprintf("identity (%d)", i))
        makeCmd.Flags().StringSliceVar(&arg_ips[i], fmt.Sprintf("ip%d",i),  []string{}, fmt.Sprintf("ip (%d)", i))
        makeCmd.Flags().StringSliceVar(&arg_cert_file[i], fmt.Sprintf("cert-file%d",i),  []string{}, fmt.Sprintf("cert from file (%d)", i))
    }

    rootCmd.AddCommand(makeCmd)


    rootCmd.AddCommand(&cobra.Command{
        Use:        "dump <infile>",
        Short:      "surface to json",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {
            f, err := ioutil.ReadFile(args[0])
            if err != nil { panic(err) }
            sf, err := surface.Parse(f);
            if err != nil { panic(err) }

            e := json.NewEncoder(os.Stdout)
            e.SetIndent("", "  ")
            e.Encode(sf)
        },
    })


    return rootCmd
}
