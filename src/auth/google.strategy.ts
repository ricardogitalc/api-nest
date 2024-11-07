import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { AuthService } from './auth.service'; // Importar o AuthService
import { Strategy, VerifyCallback } from 'passport-google-oauth20';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(private authService: AuthService) {
    // Injetar o AuthService
    super({
      clientID: process.env.GOOGLE_CLIENT_ID, // Definir variável de ambiente
      clientSecret: process.env.GOOGLE_CLIENT_SECRET, // Definir variável de ambiente
      callbackURL: `${process.env.BACKEND_URL}/auth/google/redirect`, // Usar variável de ambiente
      scope: ['email', 'profile'],
    });
  }

  async validate(profile: any): Promise<any> {
    const { emails, name } = profile;
    const email = emails[0].value;
    const firstName = name.givenName;
    const lastName = name.familyName;

    // Encontrar ou criar usuário
    const user = await this.authService.validateGoogleUser(
      email,
      firstName,
      lastName,
    );
    if (!user) {
      throw new UnauthorizedException();
    }

    return user;
  }
}
