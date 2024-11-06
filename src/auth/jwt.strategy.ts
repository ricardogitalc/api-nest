import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import { AuthService } from './auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private authService: AuthService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: configService.get('JWT_SECRET'),
    });
  }

  async validate(payload: any) {
    try {
      const decryptedData = JSON.parse(this.decryptPayload(payload.data));

      const user = await this.authService.getUser(decryptedData.email);
      if (!user) {
        throw new UnauthorizedException('Usuário não existe ou foi deletado');
      }

      return decryptedData;
    } catch (error) {
      throw new UnauthorizedException('Token inválido');
    }
  }

  private decryptPayload(encryptedData: string): string {
    const { iv, encrypted, authTag } = JSON.parse(encryptedData);

    const key = crypto.scryptSync(
      this.configService.get('JWT_SECRET'),
      'salt',
      32,
    );

    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(iv, 'hex'),
    );

    decipher.setAuthTag(Buffer.from(authTag, 'hex'));

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}
