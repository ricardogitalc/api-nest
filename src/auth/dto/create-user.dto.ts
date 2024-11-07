import {
  IsString,
  IsEmail,
  Matches,
  Length,
  IsNotEmpty,
} from 'class-validator';
import { Match } from '../decorators/match.decorator';

export class CreateUserDto {
  @IsString({ message: 'O nome deve ser uma string' })
  @Length(3, 50, { message: 'O nome deve ter entre 2 e 50 caracteres' })
  @IsNotEmpty({ message: 'O nome é obrigatório' })
  firstName: string;

  @IsString({ message: 'O sobrenome deve ser uma string' })
  @Length(3, 50, { message: 'O sobrenome deve ter entre 2 e 50 caracteres' })
  @IsNotEmpty({ message: 'O sobrenome é obrigatório' })
  lastName: string;

  @IsEmail({}, { message: 'Email inválido' })
  @IsNotEmpty({ message: 'O email é obrigatório' })
  email: string;

  @IsEmail({}, { message: 'Email de confirmação inválido' })
  @Match('email', { message: 'Os emails não são igual' })
  @IsNotEmpty({ message: 'A confirmação de email é obrigatória' })
  confirmEmail: string;

  @IsNotEmpty({ message: 'O número de WhatsApp é obrigatório' })
  @Matches(/^[1-9]\d{10}$/, {
    message: 'O número de WhatsApp deve conter 11 dígitos (ex: 11999999999)',
  })
  whatsapp: string;
}
