package carrier3


import (
    "github.com/devguardio/carrier3/v3/surface"
    ik  "github.com/devguardio/identity/go"
    "github.com/devguardio/carrier3/v3/api"

    "net"
    "context"
    "net/http"
    "fmt"
)

func Register(ctx context.Context, vault ik.VaultI, sf *surface.Surface, regkey *ik.Secret) (*api.RegistrationResponse, error) {

    dialer := surface.NewDialer(vault, sf);
    conn, ingress, err := dialer.DialContext(ctx)
    if err != nil { return nil, err }
    defer conn.Close()

    doer := &http.Client{
        Transport: &http.Transport{
            DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
                return conn, nil
            },
        },
    }

    cli, err := api.NewClientWithResponses("http://" + ingress.Name, api.WithHTTPClient(doer))
    if err != nil { return nil, err }

    rsp, err := cli.PostV1RegisterWithResponse(ctx, &api.PostV1RegisterParams{
        XAutoRegSecret: regkey.ToString(),
    })
    if err != nil { return nil, err }

    if rsp.JSON200 == nil { return nil, fmt.Errorf("%s", rsp.HTTPResponse.Status) }
	return rsp.JSON200, nil
}
