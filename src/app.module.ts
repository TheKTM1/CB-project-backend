import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { JwtModule } from '@nestjs/jwt/dist';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './Entities/user.entity';
import { Role } from './Entities/role.entity';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'sqlite',
      database: 'database/cb-db.db',
      entities: [User, Role],
      synchronize: true,
    }),
    TypeOrmModule.forFeature([User, Role]),
    JwtModule.register({
      secret: 'secret',
      signOptions: {expiresIn: '1d'}
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
