import {
  Injectable,
  BadRequestException,
  NotFoundException,
  UnauthorizedException,
  ValidationError,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { User } from '@prisma/client';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';
import { UpdateUserDto } from './dto/update-user-dto';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import {
  CreateUserTypes,
  TokenTypes,
  GoogleLoginResponse,
} from './interfaces/auth.interface';
import { LoginEmailDto } from './dto/login-email.dto';

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
    loginData: LoginEmailDto,
  ): Promise<{ tokens: TokenTypes; magicLink: string }> {
    const user = await this.prisma.user.findUnique({
      where: { email: loginData.email },
    });

    if (!user) {
      throw new BadRequestException('Usuário não encontrado');
    }

    const tokens = await this.generateTokens(user);
    const magicLink = `${this.configService.get('FRONTEND_URL')}/verify-login?token=${tokens.accessToken}`;

    return { tokens, magicLink };
  }

  async startUserRegistration(
    userData: CreateUserDto,
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
    try {
      // Primeiro encontra todos os tokens do usuário
      await this.prisma.refreshToken.deleteMany({
        where: {
          userId: userId,
        },
      });
    } catch (error) {
      console.error('Erro ao revogar refresh token:', error);
      throw new Error('Erro ao fazer logout');
    }
  }

  async createUser(createUserDto: CreateUserDto) {
    // Validar se os emails coincidem
    if (createUserDto.email !== createUserDto.confirmEmail) {
      throw new BadRequestException('Os emails não coincidem');
    }

    // Verificar se o usuário já existe
    const existingUser = await this.findByEmail(createUserDto.email);
    if (existingUser) {
      throw new BadRequestException('Email já cadastrado');
    }

    // Criar o usuário com os dados validados
    return this.prisma.user.create({
      data: {
        email: createUserDto.email,
        firstName: createUserDto.firstName,
        lastName: createUserDto.lastName,
        whatsapp: createUserDto.whatsapp,
        verified: false,
      },
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
    // Verificar se o usuário existe
    const existingUser = await this.findOne(id);
    if (!existingUser) {
      throw new NotFoundException('Usuário não encontrado');
    }

    return this.prisma.user.update({
      where: { id },
      data: {
        firstName: updateUserDto.firstName,
        lastName: updateUserDto.lastName,
        whatsapp: updateUserDto.whatsapp,
      },
    });
  }

  async remove(id: string) {
    return this.prisma.user.delete({
      where: { id },
    });
  }

  async googleLogin(googleUser: any): Promise<GoogleLoginResponse> {
    const createUserDto = new CreateUserDto();
    createUserDto.email = googleUser.email;
    createUserDto.firstName = googleUser.firstName;
    createUserDto.lastName = googleUser.lastName;
    createUserDto.whatsapp = googleUser.whatsapp || '';
    createUserDto.confirmEmail = googleUser.email; // Google já valida o email

    // O usuário do Google já é considerado verificado
    const user = await this.prisma.user.upsert({
      where: { email: createUserDto.email },
      update: {
        firstName: createUserDto.firstName,
        lastName: createUserDto.lastName,
        whatsapp: createUserDto.whatsapp,
        verified: true,
        profilePicture: googleUser.picture || '',
      },
      create: {
        email: createUserDto.email,
        firstName: createUserDto.firstName,
        lastName: createUserDto.lastName,
        whatsapp: createUserDto.whatsapp,
        verified: true,
        profilePicture: googleUser.picture || '',
      },
    });

    const tokens = await this.generateTokens(user);
    return { user, tokens };
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
