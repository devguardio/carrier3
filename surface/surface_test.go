package surface

import (
    "github.com/devguardio/identity/go"
    "testing"
    "net"
    "fmt"
    "crypto/x509"
    "encoding/base64"
    "encoding/json"
    "time"
)

func TestA(t *testing.T) {

    pk, err := identity.Vault().Identity()
    if err != nil { panic(err) }

    crt, err := pk.ToCertificate();
    if err != nil { panic(err) }

    der, err := identity.Vault().SignCertificate(crt, pk);
    if err != nil { panic(err) }

    crt , err = x509.ParseCertificate(der)
    if err != nil { panic(err) }

    var in = Surface {
        Serial:         1189,
        Precedent:      14,
        Time:           time.Now(),
        Sequencer:      *pk,
    }

    in.Ingresses[0] = Ingress{
        Name: "s1189.ingress.devguard.io",
        IP: []net.IP {
            net.ParseIP("::1"),
            net.IPv4(1,2,3,4),
        },
        Identity: pk,
    }

    in.Ingresses[1] = Ingress{
        Name: "api.devguard.io",
    }
    in.Ingresses[1].Certs = append(in.Ingresses[1].Certs, crt)

    b := in.Serialize()



    fmt.Println((&identity.Message{Key:"S", Value: b}).String());


    fmt.Println("-----BEGIN SURFACE-----")
    fmt.Println(base64.StdEncoding.EncodeToString(b))
    fmt.Println("-----END SURFACE-----")

    out, err := Parse(b)
    if err != nil { panic(err) }

    str, _ := json.MarshalIndent(out, "", "  ")
    fmt.Println(string(str))

    if in.Serial  != out.Serial {
        panic("herp")
    }

    if in.Precedent != out.Precedent {
        panic("herp")
    }

    if in.Ingresses[0].IP[0].String() != out.Ingresses[0].IP[1].String() {
        panic("burp" + out.Ingresses[0].IP[0].String())
    }

    if in.Ingresses[0].IP[1].String() != out.Ingresses[0].IP[0].String() {
        panic("burp" + out.Ingresses[0].IP[0].String())
    }

    if !in.Sequencer.Equal(&out.Sequencer) {
        panic("herp")
    }

    if !in.Sequencer.Equal(&out.Sequencer) {
        panic("herp")
    }
    if in.Time.Unix() != out.Time.Unix() {
        panic(fmt.Sprintf("%v <> %v", in.Time, out.Time))
    }

}
