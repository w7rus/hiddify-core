package request

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

type Response struct {
	StatusCode int
	Status     string
	Body       string
	Header     http.Header
}

type Method string

const (
	HEAD Method = "HEAD"
	GET  Method = "GET"
)

type Request struct {
	Method Method
	Url    string
	// SocksPort addresses a local SOCKS inbound. Set the credentials too when
	// that inbound requires them - local proxies are authenticated so other
	// processes on the machine cannot use them.
	SocksPort     uint16
	SocksUsername string
	SocksPassword string
	Timeout       time.Duration
}

func Send(req Request) (*Response, error) {
	if req.Method == "" {
		return nil, fmt.Errorf("empty method")
	}
	if req.Url == "" {
		return nil, fmt.Errorf("empty url")
	}

	httpReq, err := http.NewRequest(string(req.Method), req.Url, nil)
	if err != nil {
		return nil, err
	}

	var transport *http.Transport
	if req.SocksPort > 0 {
		var auth *proxy.Auth
		if req.SocksUsername != "" {
			auth = &proxy.Auth{User: req.SocksUsername, Password: req.SocksPassword}
		}
		dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", req.SocksPort), auth, proxy.Direct)
		if err != nil {
			return nil, err
		}

		transport = &http.Transport{
			Dial: dialer.Dial,
		}
	} else {
		transport = &http.Transport{} // Use default transport if no SOCKS5 proxy is provided
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   req.Timeout,
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	response := &Response{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Body:       string(body),
		Header:     resp.Header,
	}

	return response, nil
}
