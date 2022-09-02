import { SignInResponse } from './signin-response.interface';
import { JwtPayload } from './jwt-payload.interface';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { UsersRepository } from './users.repository';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ClientProxy, Transport, Client } from '@nestjs/microservices';

@Injectable()
export class AuthService {
  @Client({ transport: Transport.TCP })
  client: ClientProxy;

  constructor(
    @InjectRepository(UsersRepository) private usersRepository: UsersRepository,
    private jwtService: JwtService,
  ) {}

  async signUp(authCredentialsDto: AuthCredentialsDto): Promise<void> {
    return this.usersRepository.createUser(authCredentialsDto);
  }

  async signIn(
    authCredentialsDto: AuthCredentialsDto,
  ): Promise<any> {
    const { email, password } = authCredentialsDto;

    const user = await this.usersRepository.findOneBy({ email: email });

    if (user && this.isMatchedPassword(password, user.password)) {
      const payload: JwtPayload = { email };
      const accessToken: string = await this.jwtService.sign(payload);
      const response: SignInResponse = {
        email,
        phoneNumber: user.phoneNumber,
        accessToken,
      };

      return this.client.send<SignInResponse, any>('signIn', response);
      // return response;
    } else {
      throw new UnauthorizedException('Please check your login credentials');
    }
  }

  async isMatchedPassword(
    password: string,
    userPassword: string,
  ): Promise<string> {
    return await bcrypt.compare(password, userPassword);
  }
}
