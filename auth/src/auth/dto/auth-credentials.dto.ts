import { IsEmail, IsString } from 'class-validator';

export class AuthCredentialsDto {
  @IsString()
  username: string;

  @IsEmail()
  email: string;

  @IsString()
  password: string;

  @IsString()
  phoneNumber: string;
}
