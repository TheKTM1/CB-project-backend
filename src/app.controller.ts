import { Controller, Post, Body, BadRequestException } from '@nestjs/common';
import { AppService } from './app.service';
import * as bcrypt from 'bcrypt';

@Controller('api')
export class AppController {
  constructor(private readonly appService: AppService) {  //rename to UserService

  }

  @Post('register')
  async register(
    @Body('name') name: string,
    @Body('password') password: string,
    ){
      const hashedPassword = await bcrypt.hash(password, 10);

      return this.appService.create({
        name,
        password: hashedPassword
      });
  }

  @Post('login')
  async login(
    @Body('name') name: string,
    @Body('password') password: string,
  ){
    const user = await this.appService.findOne({where: {name}});

    if(!user){
      throw new BadRequestException('No user with given name has been found.');
    }

    if(!await bcrypt.compare(password, user.password)){
      throw new BadRequestException(`Given password does not match the user's password.`);
    }

    return user;
  }
}