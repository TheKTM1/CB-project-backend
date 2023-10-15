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
        roleId: 2,
        // passwordExpiration,
        mustChangePassword: true,
        passwordRestrictionsEnabled: true,
        isBlocked: false,
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

      const userResponse = {
        id: user.id,
        name: user.name,
        roleId: user.roleId,
        passwordExpiration: user.passwordExpiration,
        mustChangePassword: user.mustChangePassword,
        passwordRestrictionsEnabled: user.passwordRestrictionsEnabled,
        isBlocked: user.isBlocked,
      };

      return userResponse;
      
    } catch (e){
      console.error('Error while processing a request.');
      throw new UnauthorizedException();
    }
  }

  @Post('change-password')
  async changePassword(
    @Body('userName') name: string,
    @Body('newPassword') newPassword: string,
    @Body('oldPassword') oldPassword: string,
  ){
    const user = await this.userService.findOne({ where: {name} });

    if(!user){
      throw new BadRequestException('No user with given name has been found.');
    }

    if(!await bcrypt.compare(oldPassword, user.password)){
      throw new BadRequestException(`Given password does not match the user's password.`);
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    console.log(user);

    const update = await this.userService.update({ id: user.id }, { password: user.password });

    delete update.password;

    return update;
  }

  // @Get('users')

  @Post('logout')
  async logout(@Res({passthrough: true}) response: Response){
    response.clearCookie('jwt');

    return {
      message: 'success'
    }
  }
}