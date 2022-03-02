apis := api/openapi.gen.go

#go get github.com/deepmap/oapi-codegen/cmd/oapi-codegen



ALL: broker/broker cli/cli

broker/broker: $(apis) .PHONY
	cd broker ; go build .

cli/cli: $(apis) .PHONY
	cd cli; go build .

api/openapi.gen.go: api/openapi.yaml
	oapi-codegen -generate types,client,chi-server,spec -package api $< > $@



.PHONY:

