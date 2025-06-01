package etcd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// Client wraps the etcd client with additional functionality
type Client struct {
	client    *clientv3.Client
	watchChan chan WatchResponse
}

// WatchResponse represents a watch event response
type WatchResponse struct {
	Type  clientv3.EventType
	Key   string
	Value string
}

// CreateEtcdClient creates a new etcd client with TLS configuration
func CreateEtcdClient(endpoint, certFile, keyFile, caFile string) (*clientv3.Client, error) {
	var tlsConfig *tls.Config

	// Load client cert
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client cert/key: %v", err)
	}

	// Load CA cert
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	// Create TLS config
	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Create etcd client
	config := clientv3.Config{
		Endpoints:   []string{endpoint},
		TLS:         tlsConfig,
		DialTimeout: 5 * time.Second,
	}

	return clientv3.New(config)
}

func (c *Client) Get(ctx context.Context, key string) (string, error) {
	resp, err := c.client.Get(ctx, key)
	if err != nil {
		return "", fmt.Errorf("failed to get key %s: %v", key, err)
	}
	if len(resp.Kvs) == 0 {
		return "", fmt.Errorf("key %s not found", key)
	}
	return string(resp.Kvs[0].Value), nil
}

func (c *Client) Put(ctx context.Context, key, value string) error {
	_, err := c.client.Put(ctx, key, value)
	if err != nil {
		return fmt.Errorf("failed to put key %s: %v", key, err)
	}
	return nil
}

func (c *Client) Delete(ctx context.Context, key string) error {
	_, err := c.client.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to delete key %s: %v", key, err)
	}
	return nil
}

func (c *Client) List(ctx context.Context, prefix string) (map[string]string, error) {
	resp, err := c.client.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("failed to list keys with prefix %s: %v", prefix, err)
	}

	result := make(map[string]string)
	for _, kv := range resp.Kvs {
		result[string(kv.Key)] = string(kv.Value)
	}
	return result, nil
}

func (c *Client) Watch(ctx context.Context, key string) (<-chan WatchResponse, error) {
	if c.watchChan != nil {
		return nil, fmt.Errorf("watch already in progress for key %s", key)
	}

	c.watchChan = make(chan WatchResponse)
	go func() {
		defer close(c.watchChan)
		watchChan := c.client.Watch(ctx, key)
		for resp := range watchChan {
			for _, event := range resp.Events {
				c.watchChan <- WatchResponse{
					Type:  event.Type,
					Key:   string(event.Kv.Key),
					Value: string(event.Kv.Value),
				}
			}
		}
	}()

	return c.watchChan, nil
}

func (c *Client) Close() error {
	if c.client == nil {
		return fmt.Errorf("client is not initialized")
	}
	if err := c.client.Close(); err != nil {
		return fmt.Errorf("failed to close etcd client: %v", err)
	}
	return nil
}
