// Package api provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.8.3 DO NOT EDIT.
package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-chi/chi/v5"
)

// Connect defines model for Connect.
type Connect struct {
	Caller string `json:"Caller"`
}

// IdentifyResponse defines model for IdentifyResponse.
type IdentifyResponse struct {
	Identity string `json:"Identity"`
}

// RequestEditorFn  is the function signature for the RequestEditor callback function
type RequestEditorFn func(ctx context.Context, req *http.Request) error

// Doer performs HTTP requests.
//
// The standard http.Client implements this interface.
type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client which conforms to the OpenAPI3 specification for this service.
type Client struct {
	// The endpoint of the server conforming to this interface, with scheme,
	// https://api.deepmap.com for example. This can contain a path relative
	// to the server, such as https://api.deepmap.com/dev-test, and all the
	// paths in the swagger spec will be appended to the server.
	Server string

	// Doer for performing requests, typically a *http.Client with any
	// customized settings, such as certificate chains.
	Client HttpRequestDoer

	// A list of callbacks for modifying requests which are generated before sending over
	// the network.
	RequestEditors []RequestEditorFn
}

// ClientOption allows setting custom parameters during construction
type ClientOption func(*Client) error

// Creates a new Client, with reasonable defaults
func NewClient(server string, opts ...ClientOption) (*Client, error) {
	// create a client with sane default values
	client := Client{
		Server: server,
	}
	// mutate client and add all optional params
	for _, o := range opts {
		if err := o(&client); err != nil {
			return nil, err
		}
	}
	// ensure the server URL always has a trailing slash
	if !strings.HasSuffix(client.Server, "/") {
		client.Server += "/"
	}
	// create httpClient, if not already present
	if client.Client == nil {
		client.Client = &http.Client{}
	}
	return &client, nil
}

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HttpRequestDoer) ClientOption {
	return func(c *Client) error {
		c.Client = doer
		return nil
	}
}

// WithRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithRequestEditorFn(fn RequestEditorFn) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, fn)
		return nil
	}
}

// The interface specification for the client above.
type ClientInterface interface {
	// GetV1Identify request
	GetV1Identify(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error)

	// ConnectV1Listen request
	ConnectV1Listen(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error)

	// PostV1Listen request
	PostV1Listen(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) GetV1Identify(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetV1IdentifyRequest(c.Server)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) ConnectV1Listen(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewConnectV1ListenRequest(c.Server)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) PostV1Listen(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPostV1ListenRequest(c.Server)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewGetV1IdentifyRequest generates requests for GetV1Identify
func NewGetV1IdentifyRequest(server string) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/identify")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewConnectV1ListenRequest generates requests for ConnectV1Listen
func NewConnectV1ListenRequest(server string) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/listen")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("CONNECT", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewPostV1ListenRequest generates requests for PostV1Listen
func NewPostV1ListenRequest(server string) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/listen")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func (c *Client) applyEditors(ctx context.Context, req *http.Request, additionalEditors []RequestEditorFn) error {
	for _, r := range c.RequestEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	for _, r := range additionalEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// ClientWithResponses builds on ClientInterface to offer response payloads
type ClientWithResponses struct {
	ClientInterface
}

// NewClientWithResponses creates a new ClientWithResponses, which wraps
// Client with return type handling
func NewClientWithResponses(server string, opts ...ClientOption) (*ClientWithResponses, error) {
	client, err := NewClient(server, opts...)
	if err != nil {
		return nil, err
	}
	return &ClientWithResponses{client}, nil
}

// WithBaseURL overrides the baseURL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) error {
		newBaseURL, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		c.Server = newBaseURL.String()
		return nil
	}
}

// ClientWithResponsesInterface is the interface specification for the client with responses above.
type ClientWithResponsesInterface interface {
	// GetV1Identify request
	GetV1IdentifyWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*GetV1IdentifyResponse, error)

	// ConnectV1Listen request
	ConnectV1ListenWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*ConnectV1ListenResponse, error)

	// PostV1Listen request
	PostV1ListenWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*PostV1ListenResponse, error)
}

type GetV1IdentifyResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *IdentifyResponse
}

// Status returns HTTPResponse.Status
func (r GetV1IdentifyResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetV1IdentifyResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type ConnectV1ListenResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON101      *Connect
}

// Status returns HTTPResponse.Status
func (r ConnectV1ListenResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r ConnectV1ListenResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type PostV1ListenResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *Connect
}

// Status returns HTTPResponse.Status
func (r PostV1ListenResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r PostV1ListenResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// GetV1IdentifyWithResponse request returning *GetV1IdentifyResponse
func (c *ClientWithResponses) GetV1IdentifyWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*GetV1IdentifyResponse, error) {
	rsp, err := c.GetV1Identify(ctx, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetV1IdentifyResponse(rsp)
}

// ConnectV1ListenWithResponse request returning *ConnectV1ListenResponse
func (c *ClientWithResponses) ConnectV1ListenWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*ConnectV1ListenResponse, error) {
	rsp, err := c.ConnectV1Listen(ctx, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseConnectV1ListenResponse(rsp)
}

// PostV1ListenWithResponse request returning *PostV1ListenResponse
func (c *ClientWithResponses) PostV1ListenWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*PostV1ListenResponse, error) {
	rsp, err := c.PostV1Listen(ctx, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePostV1ListenResponse(rsp)
}

// ParseGetV1IdentifyResponse parses an HTTP response from a GetV1IdentifyWithResponse call
func ParseGetV1IdentifyResponse(rsp *http.Response) (*GetV1IdentifyResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetV1IdentifyResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest IdentifyResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	}

	return response, nil
}

// ParseConnectV1ListenResponse parses an HTTP response from a ConnectV1ListenWithResponse call
func ParseConnectV1ListenResponse(rsp *http.Response) (*ConnectV1ListenResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &ConnectV1ListenResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 101:
		var dest Connect
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON101 = &dest

	}

	return response, nil
}

// ParsePostV1ListenResponse parses an HTTP response from a PostV1ListenWithResponse call
func ParsePostV1ListenResponse(rsp *http.Response) (*PostV1ListenResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &PostV1ListenResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest Connect
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	}

	return response, nil
}

// ServerInterface represents all server handlers.
type ServerInterface interface {

	// (GET /v1/identify)
	GetV1Identify(w http.ResponseWriter, r *http.Request)

	// (CONNECT /v1/listen)
	ConnectV1Listen(w http.ResponseWriter, r *http.Request)

	// (POST /v1/listen)
	PostV1Listen(w http.ResponseWriter, r *http.Request)
}

// ServerInterfaceWrapper converts contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler            ServerInterface
	HandlerMiddlewares []MiddlewareFunc
}

type MiddlewareFunc func(http.HandlerFunc) http.HandlerFunc

// GetV1Identify operation middleware
func (siw *ServerInterfaceWrapper) GetV1Identify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetV1Identify(w, r)
	}

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler(w, r.WithContext(ctx))
}

// ConnectV1Listen operation middleware
func (siw *ServerInterfaceWrapper) ConnectV1Listen(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.ConnectV1Listen(w, r)
	}

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler(w, r.WithContext(ctx))
}

// PostV1Listen operation middleware
func (siw *ServerInterfaceWrapper) PostV1Listen(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.PostV1Listen(w, r)
	}

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler(w, r.WithContext(ctx))
}

// Handler creates http.Handler with routing matching OpenAPI spec.
func Handler(si ServerInterface) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{})
}

type ChiServerOptions struct {
	BaseURL     string
	BaseRouter  chi.Router
	Middlewares []MiddlewareFunc
}

// HandlerFromMux creates http.Handler with routing matching OpenAPI spec based on the provided mux.
func HandlerFromMux(si ServerInterface, r chi.Router) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{
		BaseRouter: r,
	})
}

func HandlerFromMuxWithBaseURL(si ServerInterface, r chi.Router, baseURL string) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{
		BaseURL:    baseURL,
		BaseRouter: r,
	})
}

// HandlerWithOptions creates http.Handler with additional options
func HandlerWithOptions(si ServerInterface, options ChiServerOptions) http.Handler {
	r := options.BaseRouter

	if r == nil {
		r = chi.NewRouter()
	}
	wrapper := ServerInterfaceWrapper{
		Handler:            si,
		HandlerMiddlewares: options.Middlewares,
	}

	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/v1/identify", wrapper.GetV1Identify)
	})
	r.Group(func(r chi.Router) {
		r.Connect(options.BaseURL+"/v1/listen", wrapper.ConnectV1Listen)
	})
	r.Group(func(r chi.Router) {
		r.Post(options.BaseURL+"/v1/listen", wrapper.PostV1Listen)
	})

	return r
}

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"H4sIAAAAAAAC/6ySsW7bQAyGX8VgOx58Urvd2qEI0KHokCXIcJZo+VLlyPIoA0agdy94klIkTtslk+nT",
	"T/LjTz5BR49MGbMWCE9QuhM+xhp+oZyxUwtZiFE04fIhjiOKRXphhABFJeUB5tmB4K8pCfYQ7jbdvdt0",
	"dHiwgrODmx6zpuPlBxamXPC6yaLQy//bPCuvG5k05SNZkR5LJ4k1UYZQp54UZTfQ7oDIuwMRgwNNOlqF",
	"LookFHBwRilLzud9s2+Mnhhz5PT85ICjniq2P7c+rcPZ/wGrgTZZtNY3PQT4inrbbhaATbO4UCt8ahr7",
	"6Sgr5pocmcfU1XT/UAxl25NFHwWPEOCD/7NIv27RX9lcHXnpBP2019lV9DEVxbz237b/En49i9v226J9",
	"hd827bvhbxf4BvXEg8R+HYipvAH6ncpfKd/T5H9Qrt7ODgqKHRKEu9eXyEI9OJhkhAAnVS7B+/X89j2e",
	"hylKv0/kYb6ffwcAAP//W9syB68DAAA=",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %s", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	var res = make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	var resolvePath = PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		var pathToFile = url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}

