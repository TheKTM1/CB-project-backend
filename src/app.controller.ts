import { Controller, Get, Post, Body, BadRequestException, UnauthorizedException, Res, Req } from '@nestjs/common';
import { AppService } from './app.service';
import { JwtService } from '@nestjs/jwt';
import { Response, Request } from 'express';
import * as bcrypt from 'bcrypt';

@Controller('api')
export class AppController {
  constructor(
    private readonly appService: AppService, //rename to UserService
    private jwtService: JwtService
  ) {

  }

  @Post('register')
  async register(
    @Body('name') name: string,
    @Body('password') password: string,
    ){
      const hashedPassword = await bcrypt.hash(password, 10);

      const user = await this.appService.create({
        name,
        password: hashedPassword
      });

      delete user.password;

      return user;
  }

  @Post('login')
  async login(
    @Body('name') name: string,
    @Body('password') password: string,
    @Res({passthrough: true}) response: Response
  ){
    const user = await this.appService.findOne({where: {name}});

    if(!user){
      throw new BadRequestException('No user with given name has been found.');
    }

    if(!await bcrypt.compare(password, user.password)){
      throw new BadRequestException(`Given password does not match the user's password.`);
    }

    const jwt = await this.jwtService.signAsync({id: user.id});

    response.cookie('jwt', jwt, {httpOnly: true});

    return {
      message: 'success'
    };
  }

  @Get('user')
  async user(@Req() request: Request){
    try{
      const cookie = request.cookies['jwt'];

      const data = await this.jwtService.verifyAsync(cookie);

      if(!data){
        throw new UnauthorizedException();
      }

      const user = await this.appService.findOne({id: data['id']});

      const {password, ...result} = user;

      return result;
      
    } catch (e){
      throw new UnauthorizedException();
    }
  }

  @Post('logout')
  async logout(@Res({passthrough: true}) response: Response){
    response.clearCookie('jwt');

    return {
      message: 'success'
    }
  }
}