import { Injectable } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';

@Injectable()
export class ThrottlerBehindProxyGuard extends ThrottlerGuard {
  protected async getTracker(req: Record<string, any>): Promise<string> {
    return req.ips.length ? req.ips[0] : req.ip;
  }

  // Sobrescrever método para ignorar certas rotas
  protected async shouldSkip(context: any): Promise<boolean> {
    // Pegar a rota da requisição
    const request = context.switchToHttp().getRequest();
    const route = request.route?.path;

    // Lista de rotas a serem ignoradas
    const skipRoutes = ['/auth/verify-login', '/auth/verify/:token'];

    return skipRoutes.includes(route);
  }
}
