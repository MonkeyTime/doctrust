export class PayloadValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "PayloadValidationError";
  }
}

export class SignatureVerificationError extends Error {
  constructor(message) {
    super(message);
    this.name = "SignatureVerificationError";
  }
}
