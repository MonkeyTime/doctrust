using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;

namespace DocumentTrustPayload;

public static class Crypto
{
    public static string Base64UrlEncode(byte[] value)
    {
        return Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static byte[] Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + ((4 - padded.Length % 4) % 4), '=');
        return Convert.FromBase64String(padded);
    }

    public static byte[] SignCanonicalPayload(string canonicalBytes, string privateKeyPem, string algorithm)
    {
        var data = Encoding.UTF8.GetBytes(canonicalBytes);

        return algorithm switch
        {
            "ES256" => SignEs256(data, privateKeyPem),
            "Ed25519" => SignEd25519(data, privateKeyPem),
            _ => throw new NotSupportedException($"Unsupported algorithm: {algorithm}")
        };
    }

    public static bool VerifyCanonicalPayload(string canonicalBytes, byte[] signature, string publicKeyPem, string algorithm)
    {
        var data = Encoding.UTF8.GetBytes(canonicalBytes);

        return algorithm switch
        {
            "ES256" => VerifyEs256(data, signature, publicKeyPem),
            "Ed25519" => VerifyEd25519(data, signature, publicKeyPem),
            _ => throw new NotSupportedException($"Unsupported algorithm: {algorithm}")
        };
    }

    private static byte[] SignEs256(byte[] data, string privateKeyPem)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(privateKeyPem);
        return ecdsa.SignData(data, HashAlgorithmName.SHA256);
    }

    private static bool VerifyEs256(byte[] data, byte[] signature, string publicKeyPem)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(publicKeyPem);
        return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
    }

    private static byte[] SignEd25519(byte[] data, string privateKeyPem)
    {
        var privateKey = ReadEd25519PrivateKey(privateKeyPem);
        var signer = new Ed25519Signer();
        signer.Init(true, privateKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    private static bool VerifyEd25519(byte[] data, byte[] signature, string publicKeyPem)
    {
        var publicKey = ReadEd25519PublicKey(publicKeyPem);
        var verifier = new Ed25519Signer();
        verifier.Init(false, publicKey);
        verifier.BlockUpdate(data, 0, data.Length);
        return verifier.VerifySignature(signature);
    }

    private static Ed25519PrivateKeyParameters ReadEd25519PrivateKey(string pem)
    {
        using var reader = new StringReader(pem);
        var pemReader = new PemReader(reader);
        var obj = pemReader.ReadObject();

        return obj switch
        {
            AsymmetricCipherKeyPair pair when pair.Private is Ed25519PrivateKeyParameters p => p,
            Ed25519PrivateKeyParameters p => p,
            PrivateKeyInfo info => new Ed25519PrivateKeyParameters(info.PrivateKey.GetOctets()),
            _ => throw new CryptographicException("Unsupported Ed25519 private key PEM")
        };
    }

    private static Ed25519PublicKeyParameters ReadEd25519PublicKey(string pem)
    {
        using var reader = new StringReader(pem);
        var pemReader = new PemReader(reader);
        var obj = pemReader.ReadObject();

        return obj switch
        {
            AsymmetricKeyParameter key when key is Ed25519PublicKeyParameters p => p,
            Ed25519PublicKeyParameters p => p,
            SubjectPublicKeyInfo info => new Ed25519PublicKeyParameters(info.PublicKey.GetBytes()),
            _ => throw new CryptographicException("Unsupported Ed25519 public key PEM")
        };
    }
}
