package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	publicKey = `-----BEGIN RSA PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxDhcx/2AEWTgZR7z7G2t
JAHvDRb+hJnWgXbjDh1URFz+d/DUaxb9fznjqzdIEKiEyFVyk2cSoyC36C8wuZ8v
Qf/KipTreQzHBZ9VqlzOCZivTzMPpdaxiqQXHN16b/V8Whs/cLoYnBXjUGiuCJ2U
0Mr9nyGAsJTWbKSyTozxvbHqGsj9mpj71tV7/NeF12X3CgswXvooGe7wtO6WYWc4
/75VgFP2fG3dql79kyQsVxYl2xHRv1+rbnBONSXQN90SI4jfgHY2yIK+QiAJaMGK
CpQXGXNZ825B7nabsapv/TEOyhfyC10gq0GP4R4Y+oVX6LmI63NYJiok2i5J9Imj
iYkEXlaNcQ6RsnPiosy+nEI7CKiTzO7mNidFGuq8j7EkDxMxLs1hVaC1GGup5NsV
WeipTAMHmcqwqHwmqmYkSOOoD4dZk46pdKelh3L2YUnsIPMkfWlVPX6dVREVSDcS
5bpbDN/4JeH3xk/2/8ABZktWDXroe70hvBvYDxByWcFNQjqCkME/MFtN4xKdLRMm
1Fk5qXciGAW191VvcUuyMbcKqNTbljAvbyo+DRY+QRkTWahtI1JmeMZb2jm+mi9v
BoQG/9OFVQ9tZczjrzfEMN4u82U4nu2ARhMtpaWGeZHX/H92HLEe75nfNl+Or5PV
dXT9/CdtF3tc9sRUXk1E6+0CAwEAAQ==
-----END RSA PUBLIC KEY-----`
	privateKey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
)

func TestParseRsaPrivateKeyFromPemStr(t *testing.T) {
	key, err := ParseRsaPrivateKeyFromPemStr(privateKey)
	require.NoError(t, err)
	require.NotNil(t, key)
}

func TestParseRsaPublicKeyFromPemStr(t *testing.T) {
	key, err := ParseRsaPublicKeyFromPemStr(publicKey)
	require.NoError(t, err)
	require.NotNil(t, key)
}

func TestExportRsaPrivateKeyAsPem(t *testing.T) {
	key, err := GenerateRsaKey()
	require.NoError(t, err)
	require.NotNil(t, key)

	var out []byte
	buf := bytes.NewBuffer(out)

	require.NoError(t, ExportRsaPrivateKeyAsPem(key, buf))
	require.True(t, len(buf.Bytes()) > 0)
}

func TestExportRsaPublicKeyAsPem(t *testing.T) {
	key, err := GenerateRsaKey()
	require.NoError(t, err)
	require.NotNil(t, key)

	var out []byte
	buf := bytes.NewBuffer(out)

	require.NoError(t, ExportRsaPublicKeyAsPem(key, buf))
	require.True(t, len(buf.Bytes()) > 0)
}

func TestGenerateRsaKey(t *testing.T) {
	key, err := GenerateRsaKey()
	require.NoError(t, err)
	require.NotNil(t, key)
}
