import {
  Body,
  Controller,
  Get,
  Logger,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { MessagePattern } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { LocalAuthGuard } from './local-auth.guard';
import { SignInResponse } from './signin-response.interface';
import { User } from './user.entity';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  @Post('/signup')
  signUp(@Body() authCredentialsDto: AuthCredentialsDto): Promise<void> {
    return this.authService.signUp(authCredentialsDto);
  }

  // @Get('/:id')
  // getGiftById(@Param('id') id: string): Promise<User> {
  //   return this.authService.getGiftById(id);
  // }

  @UseGuards(LocalAuthGuard)
  @Post('/signin')
  signIn(@Body() authCredentialsDto: AuthCredentialsDto): Promise<any> {
    return this.authService.signIn(authCredentialsDto);
  }

  @MessagePattern({ role: 'auth', cmd: 'check' })
  async loggedIn(data) {
    try {
      const res = this.authService.validateToken(data.jwt);

      return res;
    } catch (e) {
      Logger.error(e);
      return false;
    }
  }
}
