package http

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

var (
	DefaultHTTPClient = &http.Client{
		Timeout: time.Duration(30 * time.Second),
	}
)

//TODO: header (accept application/json)
//Get parses the response 
func Get(url string, response interface{}, client *http.Client) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, body)
	}
	return json.Unmarshal(body, &response)
}
