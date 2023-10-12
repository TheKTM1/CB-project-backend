import { Controller, Get, Post, Body, BadRequestException, UnauthorizedException, Res, Req } from '@nestjs/common';
import { AppService } from './app.service';
import { JwtService } from '@nestjs/jwt';
import { Response, Request } from 'express';
import * as bcrypt from 'bcrypt';

@Controller('api')
export class AppController {
  constructor(
    private readonly userService: AppService,
    private jwtService: JwtService
  ) {

  }

  @Post('register')
  async register(
    @Body('name') name: string,
    @Body('password') password: string,
    ){
      const hashedPassword = await bcrypt.hash(password, 10);

      const user = await this.userService.create({
        name,
        password: hashedPassword,
        roleid: 2,
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
    const user = await this.userService.findOne({where: {name}});

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
        console.error('No jwt data.');
        throw new UnauthorizedException();
      }

      const user = await this.userService.findOne({where: {id: data['id']} });
      const role = await this.userService.findRole({where: {id: data['roleid']}});

      const userResponse = {
        id: user.id,
        name: user.name,
        roleid: role.name,
      };

      return userResponse;
      
    } catch (e){
      console.error('Error while processing a request.');
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