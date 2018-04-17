# 50.005 NS Assignment 2

## Introduction
In	 this	 assignment,	 you	 will	implement	 a	 secure	 file	 upload	 application	 from	 a	
client	to	an	Internet	file	server.	By	secure,	we	mean	two	properties.	First,	before	
you	do	your	upload	as	the	client,	you should authenticate	the	identity	of	the	file	
server so	 you	 won’t	 leak	 your	 data	 to	 random	 entities	 including	 criminals.	
Second,	 while	 carrying	 out	 the	 upload,	 you	 should	 be	 able	 to	 protect	 the	
confidentiality	of	the	data	against	eavesdropping	by	any	curious	adversaries.

## How to run the program
- Generate a private key in der format and put in the folder
- Get a signed certificate from the Certification Authority(CA) and put it in the folder
- Get the CA's certificate and put it in the folder
- Change the path for server.crt, privateServer.der and CA.crt 
- Run ipconfig -all to get the local IP Address
- Run the ServerCP1/ServerCP2 file and CP1/CP2 file on your preferred IDE and seperate computers
- In the Server file, change the filename and path
- Run the both the Server and the Client


