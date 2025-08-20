// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"fmt"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
)

var _ CredentialProvider = (*TokenCredentialProvider)(nil)

type TokenCredentialProvider struct {
	authObj           *secretsv1beta1.VaultAuth
	providerNamespace string
	uid               types.UID
}

func NewTokenCredentialProvider(authObj *secretsv1beta1.VaultAuth, providerNamespace string,
	uid types.UID,
) *TokenCredentialProvider {
	return &TokenCredentialProvider{
		authObj,
		providerNamespace,
		uid,
	}
}

func (t *TokenCredentialProvider) GetNamespace() string {
	return t.providerNamespace
}

func (t *TokenCredentialProvider) GetUID() types.UID {
	return t.uid
}

func (t *TokenCredentialProvider) Init(ctx context.Context, client ctrlclient.Client, authObj *secretsv1beta1.VaultAuth, providerNamespace string) error {
	if authObj.Spec.Token == nil {
		return fmt.Errorf("token auth method not configured")
	}
	if err := authObj.Spec.Token.Validate(); err != nil {
		return fmt.Errorf("invalid token auth configuration: %w", err)
	}

	t.authObj = authObj
	t.providerNamespace = providerNamespace

	// Try to read the file to validate it exists and is readable
	_, err := t.readTokenFile()
	if err != nil {
		return err
	}

	// Set a static UID since we're not tied to a Kubernetes resource
	t.uid = types.UID("token-file-provider")

	return nil
}

func (t *TokenCredentialProvider) readTokenFile() (string, error) {
	filePath := t.authObj.Spec.Token.FilePath
	if filePath == "" {
		return "", fmt.Errorf("file path is empty")
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read token file %s: %w", filePath, err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("token file %s is empty or contains only whitespace", filePath)
	}

	return token, nil
}

func (t *TokenCredentialProvider) GetCreds(ctx context.Context, client ctrlclient.Client) (map[string]interface{}, error) {
	logger := log.FromContext(ctx)

	token, err := t.readTokenFile()
	if err != nil {
		logger.Error(err, "Failed to read token from file")
		return nil, err
	}

	// credentials needed for token auth - just the token value
	return map[string]interface{}{
		"token": token,
	}, nil
}
