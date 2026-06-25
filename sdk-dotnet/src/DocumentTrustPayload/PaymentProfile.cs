namespace DocumentTrustPayload;

public sealed record PaymentProfileExpectation(
    string? DocumentType = null,
    string? BeneficiaryName = null,
    string? Iban = null,
    decimal? Amount = null,
    string? Currency = null,
    string? Reference = null,
    string? DueDate = null,
    string? TransactionId = null,
    string? Communication = null);

public sealed record PaymentProfileValidationResult(
    bool Ok,
    string Profile,
    IReadOnlyList<string> MissingFields,
    IReadOnlyList<string> Mismatches);
