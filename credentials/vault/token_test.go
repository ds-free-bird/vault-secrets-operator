// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
)

func TestTokenCredentialProvider_Init(t *testing.T) {
	ctx := context.Background()
	providerNamespace := "test-provider-namespace"

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, secretsv1beta1.AddToScheme(scheme))

	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "token-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a valid token file
	validTokenFile := filepath.Join(tempDir, "valid-token")
	require.NoError(t, os.WriteFile(validTokenFile, []byte("vault-token-value"), 0600))

	// Create an empty token file
	emptyTokenFile := filepath.Join(tempDir, "empty-token")
	require.NoError(t, os.WriteFile(emptyTokenFile, []byte(""), 0600))

	// Create a whitespace-only token file
	whitespaceTokenFile := filepath.Join(tempDir, "whitespace-token")
	require.NoError(t, os.WriteFile(whitespaceTokenFile, []byte("   \n\t  "), 0600))

	tests := map[string]struct {
		authObj     *secretsv1beta1.VaultAuth
		expectedErr string
	}{
		"success": {
			authObj: &secretsv1beta1.VaultAuth{
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "token",
					Token: &secretsv1beta1.VaultAuthConfigToken{
						FilePath: validTokenFile,
					},
				},
			},
		},
		"missing token config": {
			authObj: &secretsv1beta1.VaultAuth{
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "token",
				},
			},
			expectedErr: "token auth method not configured",
		},
		"invalid token config - empty filePath": {
			authObj: &secretsv1beta1.VaultAuth{
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "token",
					Token: &secretsv1beta1.VaultAuthConfigToken{
						FilePath: "",
					},
				},
			},
			expectedErr: "invalid token auth configuration: empty filePath",
		},
		"file not found": {
			authObj: &secretsv1beta1.VaultAuth{
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "token",
					Token: &secretsv1beta1.VaultAuthConfigToken{
						FilePath: "/non/existent/path",
					},
				},
			},
			expectedErr: "failed to read token file /non/existent/path",
		},
		"empty token file": {
			authObj: &secretsv1beta1.VaultAuth{
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "token",
					Token: &secretsv1beta1.VaultAuthConfigToken{
						FilePath: emptyTokenFile,
					},
				},
			},
			expectedErr: "token file " + emptyTokenFile + " is empty or contains only whitespace",
		},
		"whitespace-only token file": {
			authObj: &secretsv1beta1.VaultAuth{
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "token",
					Token: &secretsv1beta1.VaultAuthConfigToken{
						FilePath: whitespaceTokenFile,
					},
				},
			},
			expectedErr: "token file " + whitespaceTokenFile + " is empty or contains only whitespace",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				Build()

			provider := &TokenCredentialProvider{}
			err := provider.Init(ctx, fakeClient, tc.authObj, providerNamespace)

			if tc.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.authObj, provider.authObj)
				assert.Equal(t, providerNamespace, provider.providerNamespace)
				assert.Equal(t, types.UID("token-file-provider"), provider.uid)
			}
		})
	}
}

func TestTokenCredentialProvider_GetCreds(t *testing.T) {
	ctx := context.Background()
	providerNamespace := "test-provider-namespace"

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, secretsv1beta1.AddToScheme(scheme))

	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "token-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a valid token file
	validTokenFile := filepath.Join(tempDir, "valid-token")
	require.NoError(t, os.WriteFile(validTokenFile, []byte("vault-token-value"), 0600))

	// Create a token file with whitespace
	tokenWithWhitespaceFile := filepath.Join(tempDir, "token-with-whitespace")
	require.NoError(t, os.WriteFile(tokenWithWhitespaceFile, []byte("  vault-token-value\n  "), 0600))

	// Create an empty token file
	emptyTokenFile := filepath.Join(tempDir, "empty-token")
	require.NoError(t, os.WriteFile(emptyTokenFile, []byte(""), 0600))

	tests := map[string]struct {
		authObj       *secretsv1beta1.VaultAuth
		expectedCreds map[string]interface{}
		expectedErr   string
	}{
		"success": {
			authObj: &secretsv1beta1.VaultAuth{
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "token",
					Token: &secretsv1beta1.VaultAuthConfigToken{
						FilePath: validTokenFile,
					},
				},
			},
			expectedCreds: map[string]interface{}{
				"token": "vault-token-value",
			},
		},
		"success with whitespace trimming": {
			authObj: &secretsv1beta1.VaultAuth{
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "token",
					Token: &secretsv1beta1.VaultAuthConfigToken{
						FilePath: tokenWithWhitespaceFile,
					},
				},
			},
			expectedCreds: map[string]interface{}{
				"token": "vault-token-value",
			},
		},
		"file not found": {
			authObj: &secretsv1beta1.VaultAuth{
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "token",
					Token: &secretsv1beta1.VaultAuthConfigToken{
						FilePath: "/non/existent/path",
					},
				},
			},
			expectedErr: "failed to read token file /non/existent/path",
		},
		"empty token file": {
			authObj: &secretsv1beta1.VaultAuth{
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "token",
					Token: &secretsv1beta1.VaultAuthConfigToken{
						FilePath: emptyTokenFile,
					},
				},
			},
			expectedErr: "token file " + emptyTokenFile + " is empty or contains only whitespace",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				Build()

			provider := &TokenCredentialProvider{
				authObj:           tc.authObj,
				providerNamespace: providerNamespace,
			}

			creds, err := provider.GetCreds(ctx, fakeClient)

			if tc.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErr)
				assert.Nil(t, creds)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedCreds, creds)
			}
		})
	}
}

func TestTokenCredentialProvider_GetNamespace(t *testing.T) {
	namespace := "test-namespace"
	provider := &TokenCredentialProvider{
		providerNamespace: namespace,
	}

	assert.Equal(t, namespace, provider.GetNamespace())
}

func TestTokenCredentialProvider_GetUID(t *testing.T) {
	uid := types.UID("test-uid")
	provider := &TokenCredentialProvider{
		uid: uid,
	}

	assert.Equal(t, uid, provider.GetUID())
}

func TestNewTokenCredentialProvider(t *testing.T) {
	authObj := &secretsv1beta1.VaultAuth{}
	namespace := "test-namespace"
	uid := types.UID("test-uid")

	provider := NewTokenCredentialProvider(authObj, namespace, uid)

	assert.Equal(t, authObj, provider.authObj)
	assert.Equal(t, namespace, provider.providerNamespace)
	assert.Equal(t, uid, provider.uid)
}

func TestTokenCredentialProvider_readTokenFile(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "token-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	tests := map[string]struct {
		fileContent   string
		filePerms     os.FileMode
		expectedToken string
		expectedErr   string
	}{
		"valid token": {
			fileContent:   "my-vault-token",
			filePerms:     0600,
			expectedToken: "my-vault-token",
		},
		"token with whitespace": {
			fileContent:   "  my-vault-token\n  ",
			filePerms:     0600,
			expectedToken: "my-vault-token",
		},
		"empty file": {
			fileContent: "",
			filePerms:   0600,
			expectedErr: "is empty or contains only whitespace",
		},
		"whitespace only": {
			fileContent: "   \n\t  ",
			filePerms:   0600,
			expectedErr: "is empty or contains only whitespace",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Create test file
			testFile := filepath.Join(tempDir, name+"-token")
			require.NoError(t, os.WriteFile(testFile, []byte(tc.fileContent), tc.filePerms))

			provider := &TokenCredentialProvider{
				authObj: &secretsv1beta1.VaultAuth{
					Spec: secretsv1beta1.VaultAuthSpec{
						Token: &secretsv1beta1.VaultAuthConfigToken{
							FilePath: testFile,
						},
					},
				},
			}

			token, err := provider.readTokenFile()

			if tc.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedToken, token)
			}
		})
	}
}

func TestTokenCredentialProvider_readTokenFile_EmptyFilePath(t *testing.T) {
	provider := &TokenCredentialProvider{
		authObj: &secretsv1beta1.VaultAuth{
			Spec: secretsv1beta1.VaultAuthSpec{
				Token: &secretsv1beta1.VaultAuthConfigToken{
					FilePath: "",
				},
			},
		},
	}

	token, err := provider.readTokenFile()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file path is empty")
	assert.Empty(t, token)
}
