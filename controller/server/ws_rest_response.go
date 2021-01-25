package server

import (
	"net/http"
)

type WSRestResponse struct {
	Headers http.Header
	Body    []byte
	Status  int
}

func NewWSRestResponse() *WSRestResponse {
	return &WSRestResponse{
		Headers: make(http.Header),
	}
}

func (r *WSRestResponse) Header() http.Header {
	return r.Headers
}

func (r *WSRestResponse) Write(body []byte) (int, error) {
	r.Body = body
	return len(body), nil
}

func (r *WSRestResponse) WriteHeader(status int) {
	r.Status = status
}
