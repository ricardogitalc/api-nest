// src/auth/interceptors/auth.interceptor.ts
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  UnauthorizedException,
} from '@nestjs/common';
import { Observable, throwError, from } from 'rxjs'; // Adicionar import do from
import { catchError, switchMap } from 'rxjs/operators';
import { AuthService } from '../auth.service';
import { Tokens } from '../interfaces/tokens.interface'; // Adicionar import da interface

@Injectable()
export class AuthInterceptor implements NestInterceptor {
  constructor(private authService: AuthService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      catchError((error) => {
        if (
          error instanceof UnauthorizedException &&
          error.message === 'Token expirado'
        ) {
          const request = context.switchToHttp().getRequest();
          const refreshToken = request.cookies['refresh_token'];

          if (!refreshToken) {
            return throwError(
              () => new UnauthorizedException('Refresh token não encontrado'),
            );
          }

          // Converter Promise em Observable usando from
          return from(this.authService.refreshAccessToken(refreshToken)).pipe(
            switchMap((tokens: Tokens) => {
              request.headers.authorization = `Bearer ${tokens.accessToken}`;

              // Reenviar requisição original com novo token
              return next.handle();
            }),
          );
        }
        return throwError(() => error);
      }),
    );
  }
}
