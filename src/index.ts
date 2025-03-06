export class HttpError extends Error {
    statusCode: number;
    data: any;

    constructor(message: string, statusCode: number, data = null) {
        super(message);
        this.name = 'HttpError';
        this.statusCode = statusCode;
        this.data = data;
    }
}


export interface FirebaseUser {
    kind: string;
    localId: string;
    email: string;
    displayName: string;
    idToken: string;
    registered: boolean;
    refreshToken: string;
    expiresIn: string;
}

export interface FirebaseCustomTokenResponse {   
    kind: string;
    idToken: string;
    refreshToken: string;
    expiresIn: string;
}

export interface FirebaseSignupResponse {
    kind: string;
    idToken: string;
    email: string;
    refreshToken: string;
    expiresIn: string;
    localId: string;
}

export interface FirebaseRefreshTokenResponse {
    access_token: string;
    expires_in: string;
    token_type: string;
    refresh_token: string;
    id_token: string;
    user_id: string;
    project_id: string;
}

export interface FirebaseAuthURIResponse {
    kind: string;
    allProviders?: Array<'password'>;
    registered: boolean;
    sessionId: string;
    signinMethods?: Array<'password'>;
}

export interface FirebaseUpdateProfileResponse {
    kind: string;
    localId: string;
    email: string;
    displayName: string;
    providerUserInfo: ProviderUserInfo[];
    passwordHash: string;
    emailVerified: boolean;
}

export interface FirebaseConfirmEmailResponse {
    kind: string;
    email: string;
    providerUserInfo: ProviderUserInfo[];
    passwordHash: string;
    emailVerified: boolean;
    localId: string;
}

export interface FirebaseDeleteResponse {
    kind: string;
}

export interface FirebaseVerifyEmailResponse {
    kind: string;
    email: string;
}

export interface ProviderUserInfo {
    providerId: string;
    displayName?: string;
    federatedId: string;
    email: string;
    rawId: string;
}

export interface FirebaseErrorResponse {
    error: {
        code: number;
        message: string;
        errors: {
            message: string;
            domain: string;
            reason: string;
        }[];
    };
}

export interface LookupInfoResponse {
    kind: string;
    users: Array<{
        localId: string;
        email: string;
        displayName?: string;
        passwordHash: string;
        emailVerified: boolean;
        passwordUpdatedAt: number;
        providerUserInfo: Array<{
            providerId: string;
            federatedId: string;
            email: string;
            rawId: string;
        }>;
        validSince: string;
        lastLoginAt: string;
        createdAt: string;
        lastRefreshAt: string;
    }>;
}

export interface FirebaseChangeEmailResponse {
    idToken?: string;
    refreshToken?: string;
    expiresIn?: string;
    localId: string;
    email: string;
    providerUserInfo: ProviderUserInfo[];
    passwordHash: string;
}

export interface FirebaseChangePasswordResponse {
    idToken?: string;
    refreshToken?: string;
    expiresIn?: string;
    localId: string;
    email: string;
    providerUserInfo: ProviderUserInfo[];
    passwordHash: string;
}

export interface FirebaseLinkResponse {
    idToken?: string;
    refreshToken?: string;
    expiresIn?: string;
    localId: string;
    email: string;
    displayName?: string;
    photoUrl?: string;
    passwordHash: string;
    providerUserInfo: ProviderUserInfo[];
    emailVerified: boolean;
}


//https://firebase.google.com/docs/reference/rest/auth

export class FirebaseAuthSDK {
    apiKey: string;
    tokenUrl = 'https://securetoken.googleapis.com/v1/token';
    baseUrl = 'https://identitytoolkit.googleapis.com/v1/accounts';

    constructor(apiKey: string) {
        if (!apiKey) {
            throw new Error('API key is required to use FirebaseAuth');
        }
        this.apiKey = apiKey;
    }

    async request(endpoint: string, body: any) {
        const url = `${this.baseUrl}:${endpoint}?key=${this.apiKey}`;
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error?.message || 'Request failed');
        }
        return data;
    }

    async signUp(email: string, password: string): Promise<FirebaseSignupResponse> {
        return this.request('signUp', {
            email,
            password,
            returnSecureToken: true,
        });
    }

    async signIn(email: string, password: string): Promise<FirebaseUser> {
        return this.request('signInWithPassword', {
            email,
            password,
            returnSecureToken: true,
        });
    }

    async updateProfile(params: {
        idToken: string;
        displayName?: string;
        photoUrl?: string;
        deleteAttribute?: Array<'DISPLAY_NAME' | 'PHOTO_URL'>;
    }): Promise<FirebaseUpdateProfileResponse> {
        return this.request('update', {
            idToken: params.idToken,
            displayName: params.displayName,
            photoUrl: params.photoUrl,
            deleteAttribute: params.deleteAttribute,
        });
    }

    async sendPasswordReset(email: string) {
        return this.request('sendOobCode', {
            requestType: 'PASSWORD_RESET',
            email,
        });
    }

    async createAuthRUI(email: string, continueUri: string) {
        const response = await fetch(`${this.baseUrl}:createAuthUri?key=${this.apiKey}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                identifier: email,
                continueUri,
            }),
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error?.message || 'Failed to fetch sign-in methods');
        }
        return data as FirebaseAuthURIResponse;
    }

    async verifyPasswordReset(oobCode: string, newPassword: string) {
        return this.request('resetPassword', {
            oobCode,
            newPassword,
        });
    }

    async refreshToken(refreshToken: string) {
        const response = await fetch(`${this.tokenUrl}?key=${this.apiKey}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                grant_type: 'refresh_token',
                refresh_token: refreshToken,
            }),
        });

        const data = await response.json();
        if (!response.ok) {
            throw new HttpError(data.error?.message || 'Token refresh failed', response.status, data);
        }
        return data as FirebaseRefreshTokenResponse;
    }

    async getUser(authToken: string) {
        const response = await this.request('lookup', {
            idToken: authToken,
        });
        return response as LookupInfoResponse;
    }

    isTokenValid(idToken: string | null) {
        if (!idToken) {
            return false;
        }
        try {
            const payloadBase64 = idToken.split('.')[1];
            const payloadJson = atob(payloadBase64);
            const payload = JSON.parse(payloadJson);
            const currentTime = Math.floor(Date.now() / 1000);
            return payload.exp > currentTime;
        } catch {
            return false;
        }
    }

    async sendEmailVerification(idToken: string) {
        return this.request('sendOobCode', {
            requestType: 'VERIFY_EMAIL',
            idToken,
        }) as Promise<FirebaseVerifyEmailResponse | FirebaseErrorResponse>;
    }

    async confirmEmailVerification(oobCode: string) {
        return this.request('update', {
            oobCode,
        }) as Promise<FirebaseConfirmEmailResponse | FirebaseErrorResponse>;
    }

    async deleteAccount(idToken: string) {
        return this.request('delete', {
            idToken,
        }) as Promise<FirebaseDeleteResponse | FirebaseErrorResponse>;
    }

    async changeEmail(idToken: string, newEmail: string, returnSecureToken = true) {
        return this.request('update', {
            idToken,
            email: newEmail,
            returnSecureToken,
        }) as Promise<FirebaseChangeEmailResponse | FirebaseErrorResponse>;
    }

    async changePassword(idToken: string, newPassword: string, returnSecureToken = true) {
        return this.request('update', {
            idToken,
            password: newPassword,
            returnSecureToken,
        }) as Promise<FirebaseChangePasswordResponse | FirebaseErrorResponse>;
    }

    async signInAnonymously() {
        return this.request('signUp', {
            returnSecureToken: true,
        }) as Promise<FirebaseSignupResponse | FirebaseErrorResponse>;
    }

    async signInWithCustomToken(token: string) {
        return this.request('signInWithCustomToken', {
            token,
            returnSecureToken: true,
        }) as Promise<FirebaseCustomTokenResponse | FirebaseErrorResponse>;
    }


    async linkWithPassword(idToken: string, email: string, password: string) {
        return this.request('update', {
            idToken,
            email,
            password,
            returnSecureToken: true,
        }) as Promise<FirebaseLinkResponse | FirebaseErrorResponse>;
    }

    async unlinkProvider(idToken: string, deleteProvider: string[]) {
        return this.request('update', {
            idToken,
            deleteProvider,
        }) as Promise<FirebaseLinkResponse | FirebaseErrorResponse>;
    }

    async isEmailRegistered(email: string) {
        const response = await this.createAuthRUI(email, 'http://localhost');

        return response.registered;
    }
}
