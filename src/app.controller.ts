import { Controller, Get, Post, Body, BadRequestException, UnauthorizedException, ForbiddenException, Res, Req } from '@nestjs/common';
import { AppService } from './app.service';
import { JwtService } from '@nestjs/jwt';
import { Response, Request, response } from 'express';
import { writeFile, readFileSync } from 'fs';
import { aes_decrypt, aes_encrypt } from './Scripts/crypto_functions';
import { calculate_one_time_password, convert_one_time_password } from './Scripts/one_time_password_functions'
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

      const expirationDate = new Date('2023-12-31');

      const passwordHistoryJson = {};
      passwordHistoryJson[0] = hashedPassword;

      const user = await this.userService.create({
        name,
        password: hashedPassword,
        roleId: 2,
        passwordExpiration: expirationDate,
        mustChangePassword: true,
        passwordRestrictionsEnabled: true,
        isBlocked: false,
        passwordHistory: JSON.stringify(passwordHistoryJson),
        badLoginBlockExpirationTime: null,
        sessionTimeMinutes: 15,
      });

      delete user.password;
      
      //send a log
    const currentTime = new Date();

    const logDatetimeString = currentTime.toLocaleString(undefined, {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });

    const logTimeString = currentTime.toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });

    const logStatus = `Użytkownik ${user.name} zarejestrował się.`;

    let logFile = readFileSync('database/action_log.txt', 'utf8');

    if(logFile != ''){
      logFile = aes_decrypt(logFile);
    }
    
    const logJson = logFile === '' ? {} : JSON.parse(logFile);

    logJson[Object.keys(logJson).length] = {
      "name": user.name,
      "date": logDatetimeString,
      "action": "Utworzenie konta",
      "status": logStatus,
    };

    let logString = JSON.stringify(logJson);
    
    logString = aes_encrypt(logString);

    writeFile('database/action_log.txt', logString, (error) => {
      if(error){
        console.error(error);
      }
    });

    console.log(`${logTimeString} ${logStatus}`);

      return user;
  }

  @Post('verify')
  async verify(
    @Body('name') name: string,
  ){
    const user = await this.userService.findOne({where: {name}});
    
    if(!user){
      throw new BadRequestException('No user with given name has been found.');
    }
    console.log(user.id);

    const x = Math.floor((Math.random() * 100) + 1);
    const update = await this.userService.update({
      id: user.id,
      name: name,
      password: user.password,
      roleId: user.roleId,
      passwordExpiration: user.passwordExpiration,
      mustChangePassword: user.mustChangePassword,
      passwordRestrictionsEnabled: user.passwordRestrictionsEnabled,
      isBlocked: user.isBlocked,
      passwordHistory: user.passwordHistory,
      oneTimePasswordX: x,
    });

    return x;
  }

  @Post('login')
  async login(
    @Body('name') name: string,
    @Body('password') password: string,
    @Body('oneTimePassword') oneTimePassword: string,
    @Body('captchaAnswer') captchaAnswer: string,
    @Res({passthrough: true}) response: Response
  ){
    const user = await this.userService.findOne({where: {name}});

    if(!user){
      throw new BadRequestException('No user with given name has been found.');
    }

    const currentTime = new Date();

    if(user.isBlocked){
      throw new ForbiddenException({ message: `This account has been blocked.` });
    }

    if(user.badLoginBlockExpirationTime && user.badLoginBlockExpirationTime > currentTime){
      console.log(`czas blokady: ${user.badLoginBlockExpirationTime.toLocaleString()} > czas obecny: ${currentTime.toLocaleString()}`);
      throw new ForbiddenException({ message: "This account is blocked for bad logins."});
    }

    if(!await bcrypt.compare(password, user.password)){
      throw new BadRequestException(`Given password does not match the user's password.`);
    }
 
    // if(convert_one_time_password(oneTimePassword) != calculate_one_time_password(user.oneTimePasswordX, user.name)){
    //   throw new BadRequestException(`Given one time password does not match the user's one time password.`);
    // }

    if(captchaAnswer.toUpperCase() != "DRZEWO") {
      throw new BadRequestException(`Given captcha answer does not match the answer.`);
    }

    const jwt = await this.jwtService.signAsync({id: user.id});
    
    response.cookie('jwt', jwt, {httpOnly: true});

    //send a log
    const logDatetimeString = currentTime.toLocaleString(undefined, {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });

    const logTimeString = currentTime.toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });

    const logStatus = `Zalogowano użytkownika ${user.name}.`;

    let logFile = readFileSync('database/action_log.txt', 'utf8');

    if(logFile != ''){
      logFile = aes_decrypt(logFile);
    }
    
    const logJson = logFile === '' ? {} : JSON.parse(logFile);

    logJson[Object.keys(logJson).length] = {
      "name": user.name,
      "date": logDatetimeString,
      "action": "Logowanie",
      "status": logStatus,
    };

    let logString = JSON.stringify(logJson);

    logString = aes_encrypt(logString);

    writeFile('database/action_log.txt', logString, (error) => {
      if(error){
        console.error(error);
      }
    });

    console.log(`${logTimeString} ${logStatus}`);

    return {
      message: 'success'
    };
  }

  @Post('block-account')
  async blockAccount(
    @Body('name') name: string,
  ){
    const user = await this.userService.findOne({where: {name}});

    if(!user){
      throw new BadRequestException('No user with given name has been found.');
    }

    const currentTime = new Date();
    const unblockTime = new Date(currentTime.getTime() + 15 * 60000);

    const block = await this.userService.update({
      id: user.id,
      name: user.name,
      password: user.password,
      roleId: user.roleId,
      passwordExpiration: user.passwordExpiration,
      mustChangePassword: user.mustChangePassword,
      passwordRestrictionsEnabled: user.passwordRestrictionsEnabled,
      isBlocked: user.isBlocked,
      passwordHistory: user.passwordHistory,
      badLoginBlockExpirationTime: unblockTime,
      sessionTimeMinutes: user.sessionTimeMinutes,
    });

    delete block.password;

    return block;
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
        passwordHistory: user.passwordHistory,
        sessionTimeMinutes: user.sessionTimeMinutes,
      };

      return userResponse;
      
    } catch (e){
      console.error('Error while processing a request.');
      throw new UnauthorizedException();
    }
  }

  @Post('verify-recaptcha')
  async verifyRecaptcha(
    @Body('token') token: string,
  ){
    let verified = false;

    const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: new URLSearchParams({
          secret: '6LdNQhwpAAAAAGqWsLxiX9GiaIB5v8s-zUkVCgT4',
          response: token,
      }),
    })
    .then(response => response.json())
    .then(responseBody => {
      verified = responseBody.success;
    });
    
    return verified;
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

    const passwordHistoryJson = user.passwordHistory === null ? {} : JSON.parse(user.passwordHistory);
    const jsonLength = Object.keys(passwordHistoryJson).length;

    Object.keys(passwordHistoryJson).forEach(async key => {
      const passwordHistoryElement = passwordHistoryJson[key];

      const isMatch = await bcrypt.compare(newPassword, passwordHistoryElement);

      if(isMatch){
        throw new BadRequestException(`This password has already been used.`);
      }
    });

    passwordHistoryJson[jsonLength] = hashedPassword;

    if(user.mustChangePassword == true){
      user.mustChangePassword = false;
    }

    const update = await this.userService.update({
      id: user.id,
      name: user.name,
      password: hashedPassword,
      roleId: user.roleId,
      passwordExpiration: user.passwordExpiration,
      mustChangePassword: user.mustChangePassword,
      passwordRestrictionsEnabled: user.passwordRestrictionsEnabled,
      isBlocked: user.isBlocked,
      passwordHistory: JSON.stringify(passwordHistoryJson),
      badLoginBlockExpirationTime: user.badLoginBlockExpirationTime,
      sessionTimeMinutes: user.sessionTimeMinutes,
    });

    delete update.password;

    //send a log
    const currentTime = new Date();

    const logDatetimeString = currentTime.toLocaleString(undefined, {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });

    const logTimeString = currentTime.toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });

    const logStatus = `Użytkownik ${user.name} zmienił hasło.`;

    let logFile = readFileSync('database/action_log.txt', 'utf8');

    if(logFile != ''){
      logFile = aes_decrypt(logFile);
    }
    
    const logJson = logFile === '' ? {} : JSON.parse(logFile);

    logJson[Object.keys(logJson).length] = {
      "name": user.name,
      "date": logDatetimeString,
      "action": "Zmiana hasła",
      "status": logStatus,
    };

    let logString = JSON.stringify(logJson);
    
    logString = aes_encrypt(logString);

    writeFile('database/action_log.txt', logString, (error) => {
      if(error){
        console.error(error);
      }
    });

    console.log(`${logTimeString} ${logStatus}`);

    return update;
  }

  @Post('update-account')
  async updateAccount(
    @Body('id') id: number,
    @Body('name') name: string,
    @Body('roleId') roleId: number,
    @Body('passwordExpiration') passwordExpiration: Date,
    @Body('mustChangePassword') mustChangePassword: boolean,
    @Body('passwordRestrictionsEnabled') passwordRestrictionsEnabled: boolean,
    @Body('isBlocked') isBlocked: boolean,
    @Body('sessionTimeMinutes') sessionTimeMinutes: number,
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
      passwordExpiration: passwordExpiration,
      mustChangePassword: mustChangePassword,
      passwordRestrictionsEnabled: passwordRestrictionsEnabled,
      isBlocked: isBlocked,
      passwordHistory: fetchedUser.passwordHistory,
      badLoginBlockExpirationTime: null,
      sessionTimeMinutes: sessionTimeMinutes,
    });

    delete update.password;

    //send a log
    const currentTime = new Date();

    const logDatetimeString = currentTime.toLocaleString(undefined, {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });

    const logTimeString = currentTime.toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });

    const logStatus = `Zmieniono uprawnienia użytkownika ${fetchedUser.name}.`;

    let logFile = readFileSync('database/action_log.txt', 'utf8');

    if(logFile != ''){
      logFile = aes_decrypt(logFile);
    }
    
    const logJson = logFile === '' ? {} : JSON.parse(logFile);

    logJson[Object.keys(logJson).length] = {
      "name": fetchedUser.name,
      "date": logDatetimeString,
      "action": "Aktualizacja uprawnień",
      "status": logStatus,
    };

    let logString = JSON.stringify(logJson);
    
    logString = aes_encrypt(logString);

    writeFile('database/action_log.txt', logString, (error) => {
      if(error){
        console.error(error);
      }
    });

    console.log(`${logTimeString} ${logStatus}`);

    return update;
  }

  @Post('fetch-logs')
  async fetchLogs(
    @Body('id') id: number,
  ){
    const user = await this.userService.findOne({ where: {id} });

    let logFile = readFileSync('database/action_log.txt', 'utf8');

    if(logFile != ''){
      logFile = aes_decrypt(logFile);
    }
    
    const logJson = logFile === '' ? {} : JSON.parse(logFile) as {[key: string]: {name: string}};
    
    const logArray = Object.entries(logJson);
    const result = Object.fromEntries(logArray.filter(([key, value]) => value.name === user.name));

    return result;
  }

  @Post('drop-account')
  async dropAccount(
    @Body('id') id: number,
  ){
    const fetchedUser = await this.userService.findOne({where: {id}});

    if(!fetchedUser){
      throw new BadRequestException('No user with given name has been found.');
    }

    //send a log
    const currentTime = new Date();

    const logDatetimeString = currentTime.toLocaleString(undefined, {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });

    const logTimeString = currentTime.toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });

    const logStatus = `Usunięto użytkownika ${fetchedUser.name}.`;

    let logFile = readFileSync('database/action_log.txt', 'utf8');

    if(logFile != ''){
      logFile = aes_decrypt(logFile);
    }
    
    const logJson = logFile === '' ? {} : JSON.parse(logFile);

    logJson[Object.keys(logJson).length] = {
      "name": fetchedUser.name,
      "date": logDatetimeString,
      "action": "Skasowanie",
      "status": logStatus,
    };

    let logString = JSON.stringify(logJson);
    
    logString = aes_encrypt(logString);

    writeFile('database/action_log.txt', logString, (error) => {
      if(error){
        console.error(error);
      }
    });

    console.log(`${logTimeString} ${logStatus}`);

    const drop = await this.userService.drop({
      id: fetchedUser.id,
      name: fetchedUser.name,
      password: fetchedUser.password,
      roleId: fetchedUser.roleId,
      passwordExpiration: fetchedUser.passwordExpiration,
      mustChangePassword: fetchedUser.mustChangePassword,
      passwordRestrictionsEnabled: fetchedUser.passwordRestrictionsEnabled,
      isBlocked: fetchedUser.isBlocked,
      passwordHistory: fetchedUser.passwordHistory,
      oneTimePasswordX: fetchedUser.oneTimePasswordX,

      badLoginBlockExpirationTime: fetchedUser.badLoginBlockExpirationTime,
      sessionTimeMinutes: fetchedUser.sessionTimeMinutes,
    });

    return drop;
  }

  @Post('add-account')
  async addAccount(
    @Body('name') name: string,
    @Body('password') password: string,
    @Body('roleId') roleId: number,
    @Body('passwordExpiration') passwordExpiration: Date,
    @Body('mustChangePassword') mustChangePassword: boolean,
    @Body('passwordRestrictionsEnabled') passwordRestrictionsEnabled: boolean,
    @Body('isBlocked') isBlocked: boolean,
    @Body('passwordHistory') passwordHistory: string,
    @Body('badLoginBlockExpirationTime') badLoginBlockExpirationTime: Date,
    @Body('sessionTimeMinutes') sessionTimeMinutes: number,
  ){
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await this.userService.create({
      name,
      password: hashedPassword,
      roleId,
      passwordExpiration,
      mustChangePassword,
      passwordRestrictionsEnabled,
      isBlocked,
      passwordHistory,
      badLoginBlockExpirationTime,
      sessionTimeMinutes,
    });

    delete user.password;

    //send a log
    const currentTime = new Date();

    const logDatetimeString = currentTime.toLocaleString(undefined, {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });

    const logTimeString = currentTime.toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });

    const logStatus = `Utworzono użytkownika ${user.name}.`;

    let logFile = readFileSync('database/action_log.txt', 'utf8');

    if(logFile != ''){
      logFile = aes_decrypt(logFile);
    }
    
    const logJson = logFile === '' ? {} : JSON.parse(logFile);

    logJson[Object.keys(logJson).length] = {
      "name": user.name,
      "date": logDatetimeString,
      "action": "Utworzenie konta",
      "status": logStatus,
    };

    let logString = JSON.stringify(logJson);
    
    logString = aes_encrypt(logString);

    writeFile('database/action_log.txt', logString, (error) => {
      if(error){
        console.error(error);
      }
    });

    console.log(`${logTimeString} ${logStatus}`);
    
    return user;
  }

  @Get('users')
  async users(){
    const users = await this.userService.findAll();
    return users;
  }

  @Post('logout')
  async logout(@Req() request: Request, @Res({passthrough: true}) response: Response){

    const cookie = request.cookies['jwt'];

    const data = await this.jwtService.verifyAsync(cookie);

    if(!data){
      console.error('No jwt data.');
      throw new UnauthorizedException();
    }

    const user = await this.userService.findOne({where: {id: data['id']} });

    response.clearCookie('jwt');

    //send a log
    const currentTime = new Date();

    const logDatetimeString = currentTime.toLocaleString(undefined, {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });

    const logTimeString = currentTime.toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });

    const logStatus = `Wylogowano użytkownika ${user.name}.`;

    let logFile = readFileSync('database/action_log.txt', 'utf8');

    if(logFile != ''){
      logFile = aes_decrypt(logFile);
    }
    
    const logJson = logFile === '' ? {} : JSON.parse(logFile);

    logJson[Object.keys(logJson).length] = {
      "name": user.name,
      "date": logDatetimeString,
      "action": "Wylogowanie",
      "status": logStatus,
    };

    let logString = JSON.stringify(logJson);
    
    logString = aes_encrypt(logString);

    writeFile('database/action_log.txt', logString, (error) => {
      if(error){
        console.error(error);
      }
    });

    console.log(`${logTimeString} ${logStatus}`);

    return {
      message: 'success'
    }
  }
}