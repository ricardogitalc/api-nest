import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtStrategy } from './jwt.strategy';
import { v4 as uuidv4 } from 'uuid';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { AuthInterceptor } from './interceptors/auth.interceptor';
import { GoogleStrategy } from './google.strategy';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET'),
        signOptions: {
          expiresIn: '15m', // access token expira em 15 minutos
          algorithm: 'HS512',
          issuer: 'auth-api',
          audience: 'auth-api-client',
          jwtid: uuidv4(), // Identificador único do token
        },
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [
    AuthService,
    JwtStrategy,
    GoogleStrategy,
    {
      provide: APP_INTERCEPTOR,
      useClass: AuthInterceptor,
    },
  ],
  controllers: [AuthController],
})
export class AuthModule {}
