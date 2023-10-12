import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, JoinColumn } from 'typeorm';
import { Role } from './role.entity';

@Entity('Users')
export class User {
    @PrimaryGeneratedColumn()
    id: number;

    @Column({unique: true})
    name: string;

    @Column()
    password: string;

    @ManyToOne(type => Role)
    @JoinColumn({ name: 'role' })
    roleid: Role;
}