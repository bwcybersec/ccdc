#!/bin/bash

apt install mysql-client -y

docker pull library/mysql

docker run --name mysql-server -e MYSQL_ROOT_PASSWORD=changeme -d -p 4406:3306 library/mysql 

#docker start mysql-server 

# Wait a minute while mysql starts up
echo "2 minutes..."
sleep 120

mysql -h 0.0.0.0 -P 4406 -p <<EOF
drop database if exists MyDB;
create database MyDB;
use MyDB;
create table players (playerno real,
                          name char(10),
                      initials char(4),
                 year_of_birth real,
                           sex char(1),
                   year_joined real,
                        street char(14),
                       houseno char(7),
                      postcode char(8),
                          town char(10),
                       phoneno char(10),
                      leagueno char(8));

insert into players values (  6,'Parmenter','R'   ,1964,'M',1977,
                            'Haseltine Lane','80'     ,'1234KK'  ,
                            'Stratford' ,'070-476537','8467'      ) ;
insert into players values ( 44,'Baker'    ,'E'   ,1963,'M',1980,
                            'Lewis Street'  ,'23'     ,'4444LJ'  ,
                            'Inglewood' ,'070-368753','1124'      ) ;
insert into players values ( 83,'Hope'     ,'PK'  ,1956,'M',1982,
                            'Magdalene Road','16A'    ,'1812UP'  ,
                            'Stratford' ,'070-353548','1608'      ) ;
insert into players values (  2,'Everett'  ,'R'   ,1948,'M',1975,
                            'Stoney Road'   ,'80'     ,'3575NH'  ,
                            'Stratford' ,'070-237893','2411'      ) ;
insert into players values ( 27,'Collins'  ,'DD'  ,1964,'F',1983,
                            'Long Drive'    ,'80'     ,'8457DK'  ,
                            'Eltham'    ,'070-234857','2513'      ) ;
insert into players values (104,'Moorman'  ,'D'   ,1970,'F',1984,
                            'Stout Street'  ,'80'     ,'9437AO'  ,
                            'Eltham'    ,'070-987571','7060'      ) ;
insert into players values (  7,'Wise'     ,'GWS' ,1963,'M',1981,
                            'Edgecombe Way' ,'80'     ,'9758VB'  ,
                            'Stratford' ,'070-347689','?'         ) ;
insert into players values ( 75,'Brown'    ,'M'   ,1971,'M',1985,
                            'Edgecombe Way' ,'80'     ,'4377CB'  ,
                            'Stratford' ,'070-473458','6409'      ) ;
insert into players values ( 39,'Bishop'   ,'D'   ,1956,'M',1980,
                            'Eaton Square'  ,'80'     ,'9629CD'  ,
                            'Stratford' ,'070-393435','?'         ) ;
insert into players values (112,'Bailey'   ,'IP'  ,1963,'F',1984,
                            'Vixen Road'    ,'80'     ,'6392LK'  ,
                            'Plymouth'  ,'070-548745','1319'      ) ;
insert into players values (  8,'Newcastle','B'   ,1962,'F',1980,
                            'Station Road'  ,'80'     ,'6584RO'  ,
                            'Inglewood' ,'070-458458','2983'      ) ;
insert into players values (100,'Parmenter','P'   ,1963,'M',1979,
                            'Haseltine Lane','80'     ,'1234KK'  ,
                            'Stratford' ,'070-494593','6524'      ) ;
insert into players values ( 28,'Collins'  ,'C'   ,1963,'F',1983,
                            'Old Main Road' ,'80'     ,'1294QK'  ,
                            'Midhurst'  ,'070-659599','?'         ) ;
insert into players values ( 95,'Miller'   ,'P'   ,1963,'M',1972,
                            'High Street   ','80'     ,'5476OP'  ,
                            'Douglas'   ,'070-867564','?'         ) ;


create table teams (teamno real,
                  playerno real,
                  division char(8)) ;

insert into teams values (1, 6,'first' ) ;
insert into teams values (2,27,'second') ;



create table matches (matchno real,
                       teamno real,
                     playerno real,
                          won real,
                         lost real) ;

insert into matches values ( 1,1,  6,3,1) ;
insert into matches values ( 2,1,  6,2,3) ;
insert into matches values ( 3,1,  6,3,0) ; 
insert into matches values ( 4,1, 44,3,2) ; 
insert into matches values ( 5,1, 83,0,3) ; 
insert into matches values ( 6,1,  2,1,3) ; 
insert into matches values ( 7,1, 57,3,0) ; 
insert into matches values ( 8,1,  8,0,3) ; 
insert into matches values ( 9,2, 27,3,2) ; 
insert into matches values (10,2,104,3,2) ; 
insert into matches values (11,2,112,2,3) ; 
insert into matches values (12,2,112,1,3) ; 
insert into matches values (13,2,  8,0,3) ;

create table penalties (paymentno real,
                         playerno real,
                         pen_date date, 
                           amount real) ;

insert into penalties values (1,  6,'1980-12-08',100) ;
insert into penalties values (2, 44,'1981-05-05', 75) ;
insert into penalties values (3, 27,'1983-09-10',100) ;
insert into penalties values (4,104,'1983-12-08', 50) ; 
insert into penalties values (5, 44,'1980-12-08', 25) ; 
insert into penalties values (6,  8,'1980-12-08', 25) ; 
insert into penalties values (7, 44,'1982-12-30', 30) ; 
insert into penalties values (8, 27,'1984-11-12', 75) ; 

select * from players ;

select * from teams ;

select * from matches ;

select * from penalties ;

EOF

## To revert things
# docker stop mysql-server
# docker rm mysql-server
