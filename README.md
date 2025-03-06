# Firebase Auth SDK

A lightweight TypeScript wrapper for Firebase Authentication REST API. This package provides a simple interface to interact with Firebase Authentication services without the full Firebase SDK dependency.

## Installation

```bash
npm install firebase-auth-sdk
```

## Features

- User authentication (sign up, sign in)
- Token management (refresh tokens, validate tokens)
- Profile management
- Password reset functionality
- Authentication state verification

## Usage

```ts
import { FirebaseAuthSDK } from "firebase-auth-sdk";

const auth = new FirebaseAuthSDK("your-api-key");
```

### Sign Up

```ts
const signUp = async () => {
  try {
    const user = await auth.signUp("user@example.com", "password123");
    console.log("User created:", user.localId);
  } catch (error) {
    console.error("Sign up failed:", error.message);
  }
};
```

### Sign In

```ts
const signIn = async () => {
  try {
    const user = await auth.signIn("user@example.com", "password123");
    console.log("Signed in:", user.idToken);
  } catch (error) {
    console.error("Sign in failed:", error.message);
  }
};
```

### Email Verification

```ts
const sendVerification = async (idToken: string) => {
  try {
    await auth.sendEmailVerification(idToken);
    console.log("Verification email sent");
  } catch (error) {
    console.error("Failed to send verification:", error.message);
  }
};

// When user clicks verification link, verify the OOB code
const verifyEmail = async (oobCode: string) => {
  try {
    await auth.confirmEmailVerification(oobCode);
    console.log("Email verified successfully");
  } catch (error) {
    console.error("Email verification failed:", error.message);
  }
};
```

### Password Reset

```ts
const resetPassword = async () => {
  try {
    // Send reset email
    await auth.sendPasswordReset("user@example.com");
    console.log("Password reset email sent");

    // When user clicks reset link, verify the OOB code and set new password
    const oobCode = "code-from-email";
    await auth.verifyPasswordReset(oobCode, "newPassword123");
    console.log("Password reset successful");
  } catch (error) {
    console.error("Password reset failed:", error.message);
  }
};
```

## Error Handling

The SDK throws `HttpError` for API-related errors, which includes:

- Status code
- Error message
- Additional error data (when available)

## Types

The package includes TypeScript definitions for all responses from Firebase Authentication API, including:

- `FirebaseUser`
- `FirebaseSignupResponse`
- `FirebaseRefreshTokenResponse`
- `FirebaseUpdateProfileResponse`
- `LookupInfoResponse`

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
