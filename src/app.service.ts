import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm'
import { Repository } from 'typeorm'
import { User } from './Entities/user.entity'

@Injectable()
export class AppService {
  constructor(

    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ){}

  async create(data: any): Promise<User> {
    return this.userRepository.save(data);
  }

  async update(data: any): Promise<User> {
    return this.userRepository.save(data);
  }

  async drop(data: User): Promise<User | User[]> {
    return this.userRepository.remove(data);
  }

  async findOne(condition: any): Promise<User> {
    return this.userRepository.findOne(condition);
  }

  async findAll(): Promise<User[]> {
    return this.userRepository.find();
  }
}
