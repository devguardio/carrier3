package surface

import (
    "net"
    "crypto/tls"
    "crypto/x509"
    "context"
    "time"
    "math/rand"
    ik  "github.com/devguardio/identity/go"
    log "github.com/sirupsen/logrus"
    "fmt"
    "errors"
)

type Dialer struct {
    Surface *Surface
    Vault   ik.VaultI
}

func NewDialer(vault ik.VaultI, surface *Surface) *Dialer {
    return &Dialer{
        Surface:    surface,
        Vault:      vault,
    }
}

type Verifier struct {
    Roots       *x509.CertPool
    Time        time.Time
    ServerName  string
}

func (self *Verifier) VerifyPeerCertificate (certificates [][]byte, _ [][]*x509.Certificate) error {
    certs := make([]*x509.Certificate, len(certificates))
    for i, asn1Data := range certificates {
        cert, err := x509.ParseCertificate(asn1Data)
        if err != nil {
            return errors.New("tls: failed to parse certificate from server: " + err.Error())
        }
        certs[i] = cert

        // here's the special magic.
        // if a server sends a cert that's too new, we're out of sync.
        // so we just give the validator their time as our current time
        // hoever, do NOT do the reverse, since no legitimate server should have an older document than us

        if self.Time.Before(cert.NotBefore) {
            self.Time = cert.NotBefore
        }
    }

    opts := x509.VerifyOptions{
        Roots:         self.Roots,
        CurrentTime:   self.Time,
        DNSName:       self.ServerName,
        Intermediates: x509.NewCertPool(),
    }
    for _, cert := range certs[1:] {
        opts.Intermediates.AddCert(cert)
    }
    var err error
    _ , err = certs[0].Verify(opts)
    if err != nil { return err }

    return nil
}



func selfcert(vault ik.VaultI) (tls.Certificate, error) {

    crt := tls.Certificate{}

    vaultPub, err := vault.Identity();
    if err != nil { return crt, err }

    vaultCert, err := vaultPub.ToCertificate();
    if err != nil { return crt, err }

    vaultDer, err := vault.SignCertificate(vaultCert, vaultPub);
    if err != nil { return crt, err }


    genKey, err := ik.CreateSecret();
    if err != nil { return crt, err }

    crt.PrivateKey = genKey.ToGo();

    genPub, err := genKey.Identity();
    if err != nil { return crt, err }

    genCert, err := genPub.ToCertificate();
    if err != nil { return crt, err }

    genDer, err := vault.SignCertificate(genCert, genPub);
    if err != nil { return crt, err }

    crt.Certificate = [][]byte{genDer, vaultDer}


    return crt, nil
}


func (self *Dialer) DialContext(ctx context.Context) (*tls.Conn, *Ingress, error) {

    rand.Seed(time.Now().Unix())


    selfcert, err := selfcert(self.Vault);
    if err != nil { return nil, nil, err }


    for index, ingress := range self.Surface.Ingresses {
        if ingress.Name == "" { continue }

        // fixed ips
        allIps := ingress.IP

        // lookup more ips by DNS
        ctx2, cancel := context.WithTimeout(ctx, time.Second)
        defer cancel()
        var resolver net.Resolver
        more, _ := resolver.LookupIP(ctx2, "ip", ingress.Name)
        allIps = append(allIps, more...)

        // if we have none, try the next surface
        if len(allIps) == 0 {continue}

        // randomize ips
        rand.Shuffle(len(allIps), func(i, j int) { allIps[i], allIps[j] = allIps[j], allIps[i] })

        //prepare trust
        var timestamp = self.Surface.Time
        if timestamp.IsZero() {
            timestamp = time.Now()
            log.WithField("ingress", index).Warn("surface timestamp is zero. falling back to system clock");
        }

        root := x509.NewCertPool()
        for _, cert := range ingress.Certs {
            root.AddCert(cert)
        }

        if ingress.Identity != nil {
            tpl, err := ingress.Identity.ToCertificate(ik.CertOpts{DNSNames:[]string{ingress.Name}})
            tpl.NotBefore   = timestamp.Add(-time.Hour)
            tpl.NotAfter    = timestamp.Add(time.Hour)
            if err != nil {
                der, err := self.Vault.SignCertificate(tpl, ingress.Identity)
                cert, err := x509.ParseCertificate(der)
                if err == nil {
                    root.AddCert(cert)
                }
            }
        }

        var verifier = Verifier {
            Roots:          root,
            Time:           timestamp,
            ServerName:     ingress.Name,
        }

        var tlsdialer = tls.Dialer {
            Config: &tls.Config {
                RootCAs:    root,
                Time:       func() time.Time { return timestamp },
                //NextProtos: []string{"h2", "http/1.1"},
                ServerName: ingress.Name,
                InsecureSkipVerify: true,
                VerifyPeerCertificate: verifier.VerifyPeerCertificate,
                Certificates: []tls.Certificate{selfcert},
            },
        }

        log.Println(allIps);

        // now try every ip
        for _, ip := range allIps {
            ctx2, cancel := context.WithTimeout(ctx, 5 * time.Second)
            defer cancel()
            conn, err := tlsdialer.DialContext(ctx2, "tcp", (&net.TCPAddr{
                IP: ip,
                Port: 443,
            }).String())
            if err == nil {
                return conn.(*tls.Conn), &ingress, nil
            } else {
                log.WithField("ingress", index).WithField("address", ip).Warn(err);
            }
        }
    }
    return nil, nil, fmt.Errorf("out of options");
}

