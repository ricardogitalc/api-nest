import {
  Injectable,
  BadRequestException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { User } from '@prisma/client';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';
import { UpdateUserDto } from './dto/update-user-dto';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import { CreateUserTypes, TokenTypes } from './interfaces/auth.interface';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
    private prisma: PrismaService,
  ) {}

  private readonly encryptionKey =
    process.env.ENCRYPTION_KEY || 'chave-secreta-padrao-32-caracteres';
  private readonly algorithm = 'aes-256-cbc';

  async createMagicLink(
    email: string,
  ): Promise<{ tokens: TokenTypes; magicLink: string }> {
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new BadRequestException('Usuário não encontrado');
    }

    const tokens = await this.generateTokens(user);
    const magicLink = `${this.configService.get('FRONTEND_URL')}/verify-login?token=${tokens.accessToken}`;

    return { tokens, magicLink };
  }

  async startUserRegistration(
    userData: CreateUserTypes,
  ): Promise<{ verificationToken: string; verificationLink: string }> {
    if (userData.email !== userData.confirmEmail) {
      throw new BadRequestException('Os emails não coincidem');
    }

    const existingUser = await this.prisma.user.findUnique({
      where: { email: userData.email },
    });

    if (existingUser) {
      throw new BadRequestException('Email já cadastrado');
    }

    // Criar usuário com status não verificado
    const user = await this.prisma.user.create({
      data: {
        email: userData.email,
        firstName: userData.firstName,
        lastName: userData.lastName,
        whatsapp: userData.whatsapp,
        verified: false,
      },
    });

    const token = uuidv4();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 horas

    // Criar token de verificação
    await this.prisma.verificationToken.create({
      data: {
        token,
        userId: user.id,
        expiresAt,
      },
    });

    const verificationLink = `${this.configService.get('BACKEND_URL')}/verify/${token}`;

    return {
      verificationToken: token,
      verificationLink,
    };
  }

  async verifyEmail(token: string): Promise<User> {
    const verificationToken = await this.prisma.verificationToken.findUnique({
      where: { token },
      include: { user: true },
    });

    if (!verificationToken) {
      throw new BadRequestException('Token de verificação inválido');
    }

    if (verificationToken.expiresAt < new Date()) {
      throw new BadRequestException('Token de verificação expirado');
    }

    // Atualizar usuário e remover token usando transaction
    const user = await this.prisma.$transaction(async (prisma) => {
      await prisma.verificationToken.delete({
        where: { token },
      });

      return prisma.user.update({
        where: { id: verificationToken.userId },
        data: { verified: true },
      });
    });

    return user;
  }

  async refreshAccessToken(refreshToken: string): Promise<TokenTypes> {
    const tokenRecord = await this.prisma.refreshToken.findUnique({
      where: { token: refreshToken },
      include: { user: true },
    });

    if (!tokenRecord || tokenRecord.expiresAt < new Date()) {
      throw new UnauthorizedException('Refresh token inválido ou expirado');
    }

    const user = tokenRecord.user;
    const newToken = uuidv4();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 dias

    // Atualizar refresh token
    await this.prisma.refreshToken.update({
      where: { userId: user.id },
      data: {
        token: newToken,
        expiresAt,
      },
    });

    const payload = {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      whatsapp: user.whatsapp,
      verified: user.verified,
    };

    const encryptedPayload = this.encryptPayload(payload);
    const newAccessToken = this.jwtService.sign({ data: encryptedPayload });

    return {
      accessToken: newAccessToken,
      refreshToken: newToken,
    };
  }

  async generateTokens(user: User): Promise<TokenTypes> {
    const payload = {
      data: this.encryptPayload({
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        // Outros campos, se necessário
      }),
    };

    const accessToken = this.jwtService.sign(payload, {
      expiresIn: '15m',
    });

    const refreshToken = uuidv4();

    // Salvar o refreshToken no banco de dados...

    return {
      accessToken,
      refreshToken,
    };
  }

  async getUser(email: string): Promise<User | null> {
    return this.prisma.user.findUnique({
      where: { email },
    });
  }

  async getUserById(id: string): Promise<User> {
    return this.prisma.user.findUnique({
      where: { id },
    });
  }

  private encryptPayload(payload: any): string {
    const algorithm = 'aes-256-gcm';
    const iv = crypto.randomBytes(16);
    const key = crypto.scryptSync(
      this.configService.get('JWT_SECRET'),
      'salt',
      32,
    );
    const cipher = crypto.createCipheriv(algorithm, key, iv);

    let encrypted = cipher.update(JSON.stringify(payload), 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    return JSON.stringify({
      iv: iv.toString('hex'),
      encrypted,
      authTag: authTag.toString('hex'),
    });
  }

  async decryptPayload(encryptedData: string): Promise<string> {
    try {
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
    } catch (error) {
      throw new UnauthorizedException('Erro ao descriptografar payload');
    }
  }

  async validateToken(token: string): Promise<any> {
    try {
      return this.jwtService.verify(token);
    } catch (error) {
      throw new UnauthorizedException('Token inválido ou expirado');
    }
  }

  async updateUser(id: string, updateData: UpdateUserDto): Promise<User> {
    return this.prisma.user.update({
      where: { id },
      data: updateData,
    });
  }

  async deleteUser(id: string): Promise<void> {
    await this.prisma.user.delete({
      where: { id },
    });
  }

  async revokeRefreshToken(userId: string): Promise<void> {
    // Substitua o Map.delete por uma operação do Prisma
    await this.prisma.refreshToken.delete({
      where: { userId },
    });
  }

  async createUser(createUserDto: CreateUserDto) {
    return this.prisma.user.create({
      data: createUserDto,
    });
  }

  async findAll() {
    return this.prisma.user.findMany();
  }

  async findOne(id: string) {
    return this.prisma.user.findUnique({
      where: { id },
    });
  }

  async findByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email },
    });
  }

  async update(id: string, updateUserDto: UpdateUserDto) {
    return this.prisma.user.update({
      where: { id },
      data: updateUserDto,
    });
  }

  async remove(id: string) {
    return this.prisma.user.delete({
      where: { id },
    });
  }

  async googleLogin(user: User) {
    const tokens = await this.generateTokens(user);
    await this.updateRefreshToken(user.id, tokens.refreshToken);

    return {
      message: 'Usuário autenticado com sucesso',
      tokens,
    };
  }

  async validateGoogleUser(
    email: string,
    firstName: string,
    lastName: string,
    profilePicture: string,
  ): Promise<any> {
    const user = await this.prisma.user.upsert({
      where: { email },
      update: {
        firstName,
        lastName,
        profilePicture,
        verified: true,
      },
      create: {
        email,
        firstName,
        lastName,
        profilePicture,
        verified: true,
      },
    });
    return user;
  }

  async updateRefreshToken(
    userId: string,
    refreshToken: string,
  ): Promise<void> {
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 dias

    await this.prisma.refreshToken.upsert({
      where: { userId },
      update: {
        token: refreshToken,
        expiresAt,
      },
      create: {
        userId,
        token: refreshToken,
        expiresAt,
      },
    });
  }
}
