package main

import (
	"net/http"
	"time"
)

// probeReady GETs the ready endpoint; true on 200.
func probeReady(url string) (bool, error) {
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return false, err
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}
