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
