import { IsEmail, IsNotEmpty } from 'class-validator';

export class LoginEmailDto {
  @IsEmail({}, { message: 'Email inválido' })
  @IsNotEmpty({ message: 'O email é obrigatório' })
  email: string;
}
