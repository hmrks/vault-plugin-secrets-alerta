package alertasecrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// alertaClient creates an object storing
// the client.
type alertaClient struct {
	ApiURL     string
	AuthKey    string
	HTTPClient *http.Client
}

// newClient creates a new client to access Alerta
// and exposes it for any secrets or roles to use.
func newClient(config *alertaConfig) (*alertaClient, error) {
	if config == nil {
		return nil, errors.New("client configuration was nil")
	}

	if config.ApiURL == "" {
		return nil, errors.New("client API URL was not defined")
	}

	if config.AuthKey == "" {
		return nil, errors.New("client auth key was not defined")
	}

	return &alertaClient{
		ApiURL:  config.ApiURL,
		AuthKey: config.AuthKey,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

func (c *alertaClient) makeRequest(ctx context.Context, method, endpoint string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, fmt.Sprintf("%s%s", c.ApiURL, endpoint), bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Authorization", fmt.Sprintf("Key %s", c.AuthKey))
	req.Header.Set("Content-Type", "application/json")

	return c.HTTPClient.Do(req)
}

type CreateKeyResponse struct {
	ID         string `json:"id"`
	Key        string `json:"key"`
	ExpireTime string `json:"expireTime"`
}

// should return a key, a key ID and an error
func (c *alertaClient) createKey(ctx context.Context, user string, scopes []string, text string, expireTime string) (*CreateKeyResponse, error) {
	requestBody := map[string]interface{}{
		"user":   user,
		"scopes": scopes,
		"text":   text,
	}

	if expireTime != "" {
		requestBody["expireTime"] = expireTime
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.makeRequest(ctx, "POST", "/key", jsonBody)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status code: %d, %s", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var responseData struct {
		Data struct {
			ID         string `json:"id"`
			Key        string `json:"key"`
			ExpireTime string `json:"expireTime"`
		} `json:"data"`
		Status string `json:"status"`
	}

	if err := json.Unmarshal(body, &responseData); err != nil {
		return nil, err
	}

	if responseData.Status != "ok" {
		return nil, fmt.Errorf("unexpected status: %s", responseData.Status)
	}

	return &CreateKeyResponse{
		ID:         responseData.Data.ID,
		Key:        responseData.Data.Key,
		ExpireTime: responseData.Data.ExpireTime,
	}, nil
}

type DeleteKeyResponse struct {
	Status string `json:"status"`
}

func (c *alertaClient) deleteKey(ctx context.Context, id string) (*DeleteKeyResponse, error) {
	resp, err := c.makeRequest(ctx, "DELETE", fmt.Sprintf("/key/%s", id), nil)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var responseData struct {
		Status string `json:"status"`
	}

	if err := json.Unmarshal(body, &responseData); err != nil {
		return nil, err
	}

	if responseData.Status != "ok" {
		return nil, fmt.Errorf("unexpected status: %s", responseData.Status)
	}

	return &DeleteKeyResponse{
		Status: responseData.Status,
	}, nil
}
