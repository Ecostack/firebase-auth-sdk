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
