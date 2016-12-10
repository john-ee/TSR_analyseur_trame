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
#define PUT { 80, 85, 84 }
#define HEAD { 72, 69, 65, 68 }
#define POST { 80, 79, 83, 84 }

// SMTP
#define MAIL { 77, 65, 73, 76 }
#define RCPT { 82, 67, 80, 84 }
#define DATA { 68, 65, 84, 65 }
#define EHLO { 69, 72, 76, 79 }
#define AUTH { 65, 85, 84, 72 }
#define STARTTLS { 83, 84, 65, 82, 84, 84, 76, 83 }