import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('Users')
export class User {
    @PrimaryGeneratedColumn()
    id: number;

    @Column({unique: true, nullable: false})
    name: string;

    @Column({nullable: false})
    password: string;
    
    @Column()
    roleId: number;

    @Column({nullable: true})
    passwordExpiration: Date;

    @Column()
    mustChangePassword: boolean;

    @Column()
    passwordRestrictionsEnabled: boolean;

    @Column()
    isBlocked: boolean;

    @Column({nullable: true})
    passwordHistory: string;
}