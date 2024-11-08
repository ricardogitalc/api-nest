export interface UserTypes {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  whatsapp: string;
  verified: boolean;
}

export interface CreateUserTypes {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  whatsapp: string;
  verified: boolean;
  confirmEmail: string;
}

export interface TokenTypes {
  accessToken: string;
  refreshToken: string;
}

export interface GoogleLoginResponse {
  user: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    whatsapp: string;
    profilePicture: string;
    verified: boolean;
    createdAt: Date;
    updatedAt: Date;
  };
  tokens: {
    accessToken: string;
    refreshToken: string;
  };
}
