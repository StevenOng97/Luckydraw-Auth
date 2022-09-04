import { SignInResponse } from './signin-response.interface';
import { JwtPayload } from './jwt-payload.interface';
import {
  Inject,
  Injectable,
  Logger,
  RequestTimeoutException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { UsersRepository } from './users.repository';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ClientProxy } from '@nestjs/microservices';
import { catchError, throwError, timeout, TimeoutError } from 'rxjs';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(UsersRepository)
    private usersRepository: UsersRepository,
    @Inject('USER_CLIENT')
    private client: ClientProxy,
    private jwtService: JwtService,
  ) {}

  async signUp(authCredentialsDto: AuthCredentialsDto): Promise<void> {
    return this.usersRepository.createUser(authCredentialsDto);
  }

  async signIn(user): Promise<any> {
    const loggedInUser = await this.usersRepository.findOne({
      email: user.email,
    });

    const payload = { user, sub: loggedInUser.id };

    return {
      userId: loggedInUser.id,
      accessToken: this.jwtService.sign(payload),
    };
  }

  validateToken(jwt: string) {
    return this.jwtService.verify(jwt);
  }

  // async signIn(authCredentialsDto: AuthCredentialsDto): Promise<any> {
  //   const { email, password } = authCredentialsDto;

  //   const user = await this.usersRepository.findOne({ email });
  //   if (user && this.isMatchedPassword(password, user.password)) {
  //     const payload: JwtPayload = { email };
  //     const accessToken: string = await this.jwtService.sign(payload);
  //     const response: SignInResponse = {
  //       email,
  //       phoneNumber: user.phoneNumber,
  //       accessToken,
  //     };

  //     return response;
  //   } else {
  //     throw new UnauthorizedException('Please check your login credentials');
  //   }
  // }

  async validateUser(email: string, password: string): Promise<any> {
    Logger.verbose(email);
    Logger.verbose(password);
    try {
      // const user = await this.client
      //   .send({ role: 'user', cmd: 'get' }, { email })
      //   .pipe(
      //     timeout(5000),
      //     catchError((err) => {
      //       if (err instanceof TimeoutError) {
      //         return throwError(new RequestTimeoutException());
      //       }
      //       return throwError(err);
      //     }),
      //   )
      //   .toPromise();

      // Logger.verbose(user);
      const user = await this.usersRepository.findOne({ email });

      if (this.isMatchedPassword(password, user?.password)) {
        return user;
      }

      return null;
    } catch (e) {
      Logger.log(e);
      throw e;
    }
  }

  async isMatchedPassword(
    password: string,
    userPassword: string,
  ): Promise<string> {
    return await bcrypt.compare(password, userPassword);
  }
}
