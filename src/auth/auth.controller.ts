import {
  Controller,
  Post,
  Body,
  UseGuards,
  Get,
  Request,
  Param,
  BadRequestException,
  ForbiddenException,
  Patch,
  Delete,
  Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user-dto.interface';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async register(@Body() userData: CreateUserDto) {
    const result = await this.authService.startUserRegistration(userData);
    return {
      message: 'Verifique seu email para completar o cadastro',
      ...result,
    };
  }

  @Post('login')
  async sendMagicLink(@Body('email') email: string) {
    const result = await this.authService.createMagicLink(email);
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

  @Post('refresh')
  async refreshToken(@Body() body: { refreshToken: string }) {
    return this.authService.refreshAccessToken(body.refreshToken);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(@Request() req) {
    await this.authService.revokeRefreshToken(req.user.id);
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
  async googleAuth(@Req() req) {
    // Inicia a autenticação com o Google
  }

  @Get('google/redirect')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req) {
    return this.authService.googleLogin(req.user);
  }
}
