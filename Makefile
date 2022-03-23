apis := api/openapi.gen.go

#go get github.com/deepmap/oapi-codegen/cmd/oapi-codegen



ALL: cmd/carrier3 cmd/carrier3-mipsel cmd/carrier3-mips

cmd/carrier3: $(apis) .PHONY
	cd cmd; go build -o carrier3

cmd/carrier3-mips: .PHONY
	cd cmd; CGO_ENABLED=0 GOOS=linux GOARCH=mips GOMIPS=softfloat  go build -ldflags="-s -w" -o carrier3-mips

cmd/carrier3-mipsel: .PHONY
	cd cmd; CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat  go build -ldflags="-s -w" -o carrier3-mipsel

api/openapi.gen.go: api/openapi.yaml
	oapi-codegen -generate types,client,chi-server,spec -package api $< > $@

.PHONY:

