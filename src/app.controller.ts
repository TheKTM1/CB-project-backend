import { Controller, Get, Post, Body, BadRequestException, UnauthorizedException, ForbiddenException, Res, Req } from '@nestjs/common';
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
        passwordExpiration: 1,
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

    if(user.isBlocked){
      throw new ForbiddenException({ message: `This account has been blocked.` });
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

    const update = await this.userService.update({
      id: user.id,
      name: user.name,
      password: hashedPassword,
      roleId: user.roleId,
      passwordExpiration: user.passwordExpiration,
      mustChangePassword: user.mustChangePassword,
      passwordRestrictionsEnabled: user.passwordRestrictionsEnabled,
      isBlocked: user.isBlocked
    });

    delete update.password;

    return update;
  }

  @Post('update-account')
  async updateAccount(
    @Body('id') id: number,
    @Body('name') name: string,
    @Body('roleId') roleId: number,
    @Body('mustChangePassword') mustChangePassword: boolean,
    @Body('passwordRestrictionsEnabled') passwordRestrictionsEnabled: boolean,
    @Body('isBlocked') isBlocked: boolean,
  ){
    const fetchedUser = await this.userService.findOne({where: {id}});

    if(!fetchedUser){
      throw new BadRequestException('No user with given name has been found.');
    }

    const update = await this.userService.update({
      id: fetchedUser.id,
      name: name,
      password: fetchedUser.password,
      roleId: roleId,
      passwordExpiration: fetchedUser.passwordExpiration,
      mustChangePassword: mustChangePassword,
      passwordRestrictionsEnabled: passwordRestrictionsEnabled,
      isBlocked: isBlocked
    });

    delete update.password;

    return update;
  }

  @Post('drop-account')
  async dropAccount(
    @Body('id') id: number,
  ){
    const fetchedUser = await this.userService.findOne({where: {id}});

    if(!fetchedUser){
      throw new BadRequestException('No user with given name has been found.');
    }

    const drop = await this.userService.drop({
      id: fetchedUser.id,
      name: fetchedUser.name,
      password: fetchedUser.password,
      roleId: fetchedUser.roleId,
      passwordExpiration: fetchedUser.passwordExpiration,
      mustChangePassword: fetchedUser.mustChangePassword,
      passwordRestrictionsEnabled: fetchedUser.passwordRestrictionsEnabled,
      isBlocked: fetchedUser.isBlocked
    });

    return drop;
  }

  @Post('add-account')
  async addAccount(
    @Body('name') name: string,
    @Body('password') password: string,
    @Body('roleId') roleId: number,
    @Body('passwordExpiration') passwordExpiration: number,
    @Body('mustChangePassword') mustChangePassword: boolean,
    @Body('passwordRestrictionsEnabled') passwordRestrictionsEnabled: boolean,
    @Body('isBlocked') isBlocked: boolean,
  ){
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await this.userService.create({
      name,
      password: hashedPassword,
      roleId,
      passwordExpiration,
      mustChangePassword,
      passwordRestrictionsEnabled,
      isBlocked
    });

    delete user.password;
    
    return user;
  }

  @Get('users')
  async users(){
    const users = await this.userService.findAll();
    return users;
  }

  @Post('logout')
  async logout(@Res({passthrough: true}) response: Response){
    response.clearCookie('jwt');

    return {
      message: 'success'
    }
  }
}