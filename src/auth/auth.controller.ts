import {
  Controller,
  Post,
  Body,
  UseGuards,
  Get,
  Request,
  Param,
  ForbiddenException,
  Patch,
  Delete,
  Req,
  Query,
  UnauthorizedException,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { UpdateUserDto } from './dto/update-user-dto';
import { AuthGuard } from '@nestjs/passport';
import {
  CreateUserTypes,
  GoogleLoginResponse,
} from './interfaces/auth.interface'; // Adicionada importação aqui
import { JwtService } from '@nestjs/jwt';
import { JsonWebTokenError } from 'jsonwebtoken';
import { Response } from 'express';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginEmailDto } from './dto/login-email.dto';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly jwtService: JwtService, // Adicione esta injeção
  ) {}

  @Post('register')
  async register(@Body() userData: CreateUserDto) {
    const result = await this.authService.startUserRegistration(userData);
    return {
      message: 'Verifique seu email para completar o cadastro',
      ...result,
    };
  }

  @Post('login')
  async sendMagicLink(@Body() loginData: LoginEmailDto) {
    const result = await this.authService.createMagicLink(loginData);
    return {
      message: 'Magic link gerado com sucesso!',
      ...result,
    };
  }

  @Get('verify/:token')
  async verifyEmail(@Param('token') token: string) {
    const user = await this.authService.verifyEmail(token);
    return { message: 'Email verificado com sucesso', user };
  }

  @Get('verify-login')
  async verifyLoginToken(
    @Query('token') token: string,
    @Res({ passthrough: true }) response: Response,
  ) {
    try {
      const decoded = await this.jwtService.verify(token);
      const decryptedData = await this.authService.decryptPayload(decoded.data);
      const userData = JSON.parse(decryptedData);

      const user = await this.authService.getUserById(userData.id);
      if (!user) {
        throw new UnauthorizedException('Usuário não encontrado');
      }

      const tokens = await this.authService.generateTokens(user);

      // Ajustar os cookies para serem acessíveis
      response.cookie('auth.accessToken', tokens.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: 30 * 1000, // Alterado para 30 segundos
      });

      response.cookie('auth.refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: 2 * 60 * 1000, // Alterado para 2 minutos
      });

      return {
        message: 'Login realizado com sucesso',
        user,
      };
    } catch (error) {
      throw new UnauthorizedException('Token inválido ou expirado');
    }
  }

  @Post('refresh')
  async refreshToken(
    @Body() body: { refreshToken: string },
    @Res({ passthrough: true }) response: Response,
  ) {
    try {
      const tokens = await this.authService.refreshAccessToken(
        body.refreshToken,
      );

      response.cookie('auth.accessToken', tokens.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: 30 * 1000, // Alterado para 30 segundos
      });

      response.cookie('auth.refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: 2 * 60 * 1000, // Alterado para 2 minutos
      });

      return tokens;
    } catch (error) {
      throw new UnauthorizedException('Falha ao atualizar o token');
    }
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(@Res({ passthrough: true }) response: Response, @Request() req) {
    await this.authService.revokeRefreshToken(req.user.id);

    // Limpa os cookies na resposta
    response.clearCookie('auth.accessToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
    });

    response.clearCookie('auth.refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
    });

    return { message: 'Logout realizado com sucesso' };
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  getProfile(@Request() req) {
    return req.user;
  }

  @UseGuards(JwtAuthGuard)
  @Get('users/:id')
  async getUserById(@Param('id') id: string) {
    return this.authService.getUserById(id);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('users/:id')
  async updateUser(
    @Param('id') id: string,
    @Body() updateData: UpdateUserDto, // Usando o DTO correto
    @Request() req,
  ) {
    // Verifica se o usuário está atualizando seu próprio perfil
    if (req.user.email !== (await this.authService.getUserById(id)).email) {
      throw new ForbiddenException('Você só pode atualizar seu próprio perfil');
    }

    const updatedUser = await this.authService.updateUser(id, updateData);
    return { message: 'Usuário atualizado com sucesso', user: updatedUser };
  }

  @UseGuards(JwtAuthGuard)
  @Delete('users/:id')
  async deleteUser(@Param('id') id: string, @Request() req) {
    // Verifica se o usuário está deletando seu próprio perfil
    if (req.user.email !== (await this.authService.getUserById(id)).email) {
      throw new ForbiddenException('Você só pode deletar seu próprio perfil');
    }

    await this.authService.deleteUser(id);
    return { message: 'Usuário deletado com sucesso' };
  }

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    // Inicia autenticação Google
  }

  @Get('google/redirect')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req, @Res() response: Response) {
    try {
      const result: GoogleLoginResponse = await this.authService.googleLogin(
        req.user,
      );
      const { user, tokens } = result;

      response.cookie('auth.accessToken', tokens.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
      });

      response.cookie('auth.refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
      });

      return response.redirect(
        process.env.FRONTEND_URL || 'http://localhost:3000',
      );
    } catch (error) {
      return response.redirect(
        `${process.env.FRONTEND_URL}/login?error=google-auth-failed`,
      );
    }
  }
}
