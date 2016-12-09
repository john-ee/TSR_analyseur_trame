#define UDP 0x0011
#define TCP 0x0006

//Ports de protocoles applicatifs
#define TELNET 23
#define SMTPS 587
#define SMTP 25
#define HTTP 80
#define HTTPS 443
#define DNS 53
#define BOOTPS 67 //server
#define BOOTPC 68 //client
#define DHCP 546
#define FTPS 21 //server
#define FTPC 22 //client

//HTTP
#define GET { 71, 69, 84 }
#define HEAD { 72, 69, 65, 68 }
#define POST { 80, 79, 83, 84 }
//OPTIONS, PUT, DELETE, TRACE

// SMTP
// MAIL RCPT DATA EHLO ESMTP AUTH
#define MAIL { 4D, 41, 49, 4C }
#define RCPT { 52, 43, 50, 54 }
#define DATA { 44, 41, 54, 41 }
#define EHLO { 45, 48, 4C, 4F }
#define ESMTP { 45, 53, 4D, 50, 54 }
#define AUTH { 41, 55, 54, 48 }