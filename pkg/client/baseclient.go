package lamassuca

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

type BaseClient interface {
	NewRequest(method string, path string, body interface{}) (*http.Request, error)
	Do(req *http.Request) (interface{}, *http.Response, error)
}

type ClientConfig struct {
	BaseURL    *url.URL
	httpClient *http.Client
}

func NewBaseClient(url *url.URL, httpClient *http.Client) BaseClient {
	return &ClientConfig{
		BaseURL:    url,
		httpClient: httpClient,
	}
}

func (c *ClientConfig) NewRequest(method string, path string, body interface{}) (*http.Request, error) {
	rel := &url.URL{Path: path}
	u := c.BaseURL.ResolveReference(rel)
	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err := json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}
func (c *ClientConfig) Do(req *http.Request) (interface{}, *http.Response, error) {
	var v interface{}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != 200 {
		return nil, resp, errors.New("Response with status code: " + strconv.Itoa(resp.StatusCode))
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&v)
	return v, resp, err
}
