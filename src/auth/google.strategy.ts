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

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    try {
      // Verificar se temos as informações necessárias
      if (!profile || !profile.emails || !profile.name) {
        throw new UnauthorizedException('Perfil do Google incompleto');
      }

      const email = profile.emails[0].value; // Correção do acesso ao email
      const firstName = profile.name.givenName || '';
      const lastName = profile.name.familyName || '';
      const photoUrl = profile.photos?.[0]?.value || ''; // Extraindo URL da foto

      const user = await this.authService.validateGoogleUser(
        email,
        firstName,
        lastName,
        photoUrl, // Adicionando a foto como novo parâmetro
      );

      done(null, user);
    } catch (error) {
      done(error, null);
    }
  }
}
