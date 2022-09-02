import {
  ConflictException,
  InternalServerErrorException,
} from '@nestjs/common';
import { EntityRepository, Repository } from 'typeorm';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { User } from './user.entity';
import * as bcrypt from 'bcrypt';

@EntityRepository(User)
export class UsersRepository extends Repository<User> {
  //
  async createUser(authCredentialsDto: AuthCredentialsDto): Promise<void> {
    const { email, password, username, phoneNumber } = authCredentialsDto;

    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = this.create({
      username,
      email,
      password: hashedPassword,
      phoneNumber,
    });
    try {
      await this.save(user);
    } catch (error) {
      if (error.code === '23505') {
        throw new ConflictException('Email đã tồn tại');
      } else {
        throw new InternalServerErrorException();
      }
    }
  }

  // async signIn(authCredentialsDto: AuthCredentialsDto): Promise<string>{
  //   const { email, password } = authCredentialsDto;

  //   const email = await this.UsersRepository
  // }
}
