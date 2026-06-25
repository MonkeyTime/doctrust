namespace DocumentTrustPayload;

public sealed class PayloadValidationException : Exception
{
    public PayloadValidationException(string message) : base(message) { }
}

public sealed class SignatureVerificationException : Exception
{
    public SignatureVerificationException(string message) : base(message) { }
}
