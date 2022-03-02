package surface

import (
    "github.com/devguardio/identity/go"
    "net"
    "encoding/binary"
    "fmt"
    "io"
    "crypto/x509"
    "time"
)

/*

    connection must follow this protocol:

    - parse document
        - for each ingress index, accumulate its fields.
          they are ordered by importance, so stopping on some upper bound of accumulated entries
          per index is ok.
        - stop parsing the whole document when encountering an unknown field type
          fields are ordered by type, so that newer field types are appended
    - tls connect
        - try the ingresses in order of their index. this ensures we can put fallbacks last
        - if there's a domain field, resolve the domains A and AAAA records and add them to the list of ips
        - if there's an identity generate the cert and add it to the list of trusted roots
        - set SNI field if there was a record for this ingress
        - pick a random IP and tcp connect to 443
        - validate server cert against any of the trust roots
        - if the certs notbefore is newer than our epoch date, we're out of sync, so ignore notbefore
        - but still respect notafter, to make sure we don't accept certs that are older than our last sync
        - check that either CN matches SNI or an IP SAN matches IP
          this is because we might trust a root not under our control, like letsencrypt,
          so we need to do the standard checks to make sure its actually our cert
        - send our own identity as x509 client cert
    - establish http1 or http2
        - note that alpn MUST be either empty or 'h2' and cannot be used to mux services because the way frontend LBs work
        - instead everything is implemented as http calls. that's fine with http2
    - request surface update via http get .next call
        - check that update is signed by the sequence key
        - and the precedent matches our current document serial.
        - Do NOT check that the serial is exactly +1, the order is established with the precedent field instead
        - on signature failure drop the whole connection and try the next ingress
        - if document was updated, restart from step 0
    - request current time


    yanking a root:
        - the domain put into a document is a forever promise. Devices must be able to connect to it, and http get a newer document.
        - hence the domain should include the serial, like s82.carrier.devguard.io
        - if the root is leaked, it STILL must be used to at least serve the signed document as static file on that url

    sync clock ocasionally
        every day or so we should emit a new document with nothing changed except the time.
        this ensures clients will never accept expired certs.
        no need to change the domain, since we haven't changed any roots


    DO NOT REUSE sequencer secret
        the identity in the sequencer field must be random for each document.
        We don't hash the previous document, so a reused identity can lead to a message being replayable on a different chain.
        This can be done intentionally to merge chains, but only by having both chain secrets.



    header:
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    | 1B Magic:   'S'               |
    | 1B Version: '1'               |
    | Varint  Serial                |
    | Varint  Precedent             |
    | Varint  Timestamp             |
    | 32B Sequencer identity        |
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    1: Domain
    ---------------------------------
    | 4bit  field type              |
    | 4bit  ingress index           |
    | 1byte len                     |
    | ... name                      |
    ---------------------------------

    2: ipv4 address
    ---------------------------------
    | 4bit  field type              |
    | 4bit  ingress index           |
    | 4byte ipv4                    |
    ---------------------------------

    3. ed25519 identity
    ---------------------------------
    | 4bit  field type              |
    | 4bit  ingress index           |
    | 32byte identity               |
    ---------------------------------

    4: ipv6 address
    ---------------------------------
    | 4bit  field type              |
    | 4bit  ingress index           |
    | 16byte ipv6                   |
    ---------------------------------

    5: x509 cert
    ---------------------------------
    | 4bit  field type              |
    | 4bit  ingress index           |
    | 2byte len                     |
    | ... cert                      |
    ---------------------------------
*/

const (
    RecordTypeName      = 1
    RecordTypeV4        = 2
    RecordTypeIdentity  = 3
    RecordTypeV6        = 4
    RecordTypeX509      = 5
)


type Ingress struct {
    Name        string                      `json:",omitempty"`
    Identity    *identity.Identity          `json:",omitempty"`
    Certs       []*x509.Certificate         `json:",omitempty"`
    IP          []net.IP                    `json:",omitempty"`
}

type Surface struct {
    Serial      identity.Serial
    Precedent   identity.Serial
    Sequencer   identity.Identity
    Time        time.Time
    Ingresses   [16]Ingress
}

func Parse(rr []byte) (*Surface, error) {

    if len(rr) < (1 + 1 + 8 + 8 + 8 + 32) {
        return nil, fmt.Errorf("doesn't look like a surface document: too small");
    }
    if rr[0] != 'S' {
        return nil, fmt.Errorf("doesn't look like a surface document: invalid magic");
    }
    if rr[1] != '1' {
        return nil, fmt.Errorf("carrier too old to read surface version %c", rr[1]);
    }

    var at = 2

    doc := &Surface{}

    val, ra := binary.Uvarint(rr[at:])
    at += ra
    doc.Serial  = identity.Serial(val)

    val, ra = binary.Uvarint(rr[at:])
    at += ra
    doc.Precedent = identity.Serial(val)

    val, ra = binary.Uvarint(rr[at:])
    at += ra
    doc.Time = time.Unix(int64(val), 0)

    copy(doc.Sequencer[:], rr[at:at+32])
    at += 32

    for ;; {
        if at >= len(rr) {
            break
        }

        h       := rr[at]
        typ     := (h & 0b11110000) >> 4
        index   := (h & 0b00001111)

        at += 1

        switch typ {
            case RecordTypeName:
                if at + 1 > len(rr) {return nil, io.EOF}
                l := int(rr[at])
                at += 1
                if at + l > len(rr) {return nil, io.EOF}
                doc.Ingresses[index].Name = string(rr[at: at+l])
                at += l
            case RecordTypeV4:
                if at + 4  > len(rr) {return nil, io.EOF}
                doc.Ingresses[index].IP = append(doc.Ingresses[index].IP, net.IPv4(rr[at], rr[at+1], rr[at+2], rr[at+3]))
                at += 4
            case RecordTypeIdentity:
                if at + 32 > len(rr) {return nil, io.EOF}
                doc.Ingresses[index].Identity = &identity.Identity{}
                copy(doc.Ingresses[index].Identity[:], rr[at:at+32])
                at += 32
            case RecordTypeV6:
                if at + 16 > len(rr) {return nil, io.EOF}
                doc.Ingresses[index].IP = append(doc.Ingresses[index].IP, rr[at:at+16])
                at += 16
            case RecordTypeX509:
                if at + 2 > len(rr) {return nil, io.EOF}
                l := int(binary.LittleEndian.Uint16(rr[at:at+2]))
                at += 2
                if at + l > len(rr) {return nil, io.EOF}

                crt, err := x509.ParseCertificate(rr[at: at+l])
                if err == nil {
                    doc.Ingresses[index].Certs = append(doc.Ingresses[index].Certs, crt)
                }

                at += l
            default:
                break
        }

    }

    return doc, nil
}

func (doc *Surface) Serialize() []byte {
    var b [32767]byte

    b[0] = 'S'
    b[1] = '1'

    var at = 2

    at += binary.PutUvarint(b[at:], uint64(doc.Serial))
    at += binary.PutUvarint(b[at:], uint64(doc.Precedent))
    at += binary.PutUvarint(b[at:], uint64(doc.Time.Unix()))
    copy(b[at:at+32], doc.Sequencer[:])
    at += 32


    // name
    for i, ep := range doc.Ingresses {
        if ep.Name == ""  { continue }
        s := []byte(ep.Name)
        if len(s) > 255 {s=s[:255]}
        if at + 1 + 1 + len(s) >= len(b) {
            break
        }
        b[at] = uint8(( RecordTypeName << 4 ) | i)
        at += 1
        b[at] = uint8(len(s))
        at += 1
        copy(b[at:], s[:])
        at += len(s)
    }

    // v4
    for i, ep := range doc.Ingresses {
        for _, ip := range ep.IP {
            if v4 := ip.To4() ; v4 != nil {
                if at + 1 + 4 >= len(b) {
                    break
                }
                b[at] = uint8(( RecordTypeV4 << 4 ) | i)
                at += 1
                copy(b[at:at+4], v4[:])
                at += 4
            }
        }
    }

    // identity
    for i, ep := range doc.Ingresses {
        if ep.Identity == nil { continue }

        if at + 1 + 32 >= len(b) {
            break
        }
        b[at] = uint8(( RecordTypeIdentity << 4 ) | i)
        at += 1
        copy(b[at:at+32], ep.Identity[:])
        at += 32
    }

    // v6
    for i, ep := range doc.Ingresses {
        for _, ip := range ep.IP {
            if v4 := ip.To4() ; v4 == nil {
                if at + 1 + 16 >= len(b) {
                    break
                }
                b[at] = uint8(( RecordTypeV6 << 4 ) | i)
                at += 1
                copy(b[at:at+16], ip[:])
                at += 16
            }
        }
    }

    // cert
    for i, ep := range doc.Ingresses {
        for _, cert := range ep.Certs {

            der := cert.Raw

            if der == nil || len(der) > 16000 { continue }
            if at + 1 + 2 + len(der) >= len(b) {
                break
            }

            b[at] = uint8(( RecordTypeX509 << 4 ) | i)
            at += 1
            binary.LittleEndian.PutUint16(b[at:at+2], uint16(len(der)))
            at += 2
            copy(b[at:], der[:])
            at += len(der)
        }
    }

    return b[:at]
}
