/*
 * EthernetAlarm.c
 *
 * Created: 03.05.2013 21:21:14
 *  Author: denis-m-tyurin
 */ 

#include <avr/io.h>
#include <avr/interrupt.h>
#include <stdlib.h>
#include <string.h>
#include <avr/pgmspace.h>
#include <avr/eeprom.h>
#include "ip_arp_udp_tcp.h"
#include "websrv_help_functions.h"
#include "enc28j60.h"
#include "timeout.h"
#include "net.h"

//---------------- start of modify lines --------
// please modify the following lines. mac and ip have to be unique
// in your network. You can not have the same numbers in
// two devices:
static uint8_t mymac[6] = {0x54,0x55,0x58,0x10,0x00,0x29};
// how did I get the mac addr? Translate the first 3 numbers into ascii is: TUX
static uint8_t myip[4] = {192,168,0,2};
// listen port for tcp/www:
#define MYWWWPORT 80
// listen port for udp
#define MYUDPPORT 1200
// the password string (only a-z,0-9,_ characters):
static char password[10]="sharedsec"; // must not be longer than 9 char
// MYNAME_LEN must be smaller than gStrbuf (below):
#define STR_BUFFER_SIZE 30
#define MYNAME_LEN STR_BUFFER_SIZE-14
static char myname[MYNAME_LEN+1]="section-42";
// IP address of the alarm server to contact. The server we send the UDP to
static uint8_t udpsrvip[4] = {192,168,0,1};
static uint16_t udpsrvport=5151;
// Default gateway. The ip address of your DSL router. It can be set to the same as
// udpsrvip the case where there is no default GW/router to access the
// server (=server is on the same lan as this host)
static uint8_t gwip[4] = {192,168,0,1};
//
// the alarm contact is PD3.
// ALCONTACTCLOSE=1 means: alarm when contact between GND and PD3 closed
#define ALCONTACTCLOSE 1
// alarm when contact between PD3 and GND is open
//#define ALCONTACTCLOSE 0
//---------------- end of modify lines --------
//
#define TRANS_NUM_GWMAC 1
static uint8_t gwmac[6];
static int8_t gw_arp_state=0;

#define BUFFER_SIZE 650
static uint8_t buf[BUFFER_SIZE+1];
static uint16_t gPlen;
static char gStrbuf[STR_BUFFER_SIZE+1];
static uint8_t alarmOn=1; // alarm system is on or off
static uint8_t lastAlarm=0; // indicates if we had an alarm or not
// timing:
static volatile uint8_t cnt2step=0;
static volatile uint8_t gSec=0;
static volatile uint16_t gMin=0; // alarm time min

#define ETH_LEDON PORTC|=(1<<PC5)
#define ETH_LEDOFF PORTC&=~(1<<PC5)

#define ALARM_LEDON PORTC|=(1<<PC4)
#define ALARM_LEDOFF PORTC&=~(1<<PC4)
// to test the state of the LED
#define ALARM_LEDISON PINC&(1<<PC4)

uint8_t verify_password(char *str)
{
	// the first characters of the received string are
	// a simple password/cookie:
	if (strncmp(password,str,strlen(password))==0){
		return(1);
	}
	return(0);
}

uint16_t http200ok(void)
{
	return(fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nPragma: no-cache\r\n\r\n")));
}

uint16_t print_webpage_config(void)
{
	uint16_t plen;
	plen=http200ok();
	
	// Check if gatewy MAC look-up has been already done
	if (gw_arp_state==1)
	{
	        plen=fill_tcp_data_p(buf,plen,PSTR("waiting for GW MAC\n"));
		    return(plen);
	}
	plen=fill_tcp_data_p(buf,plen,PSTR("<a href=/>[home]</a>"));
	plen=fill_tcp_data_p(buf,plen,PSTR("<h2>Alarm config</h2><pre>\n"));
	plen=fill_tcp_data_p(buf,plen,PSTR("<form action=/u method=get>"));
	plen=fill_tcp_data_p(buf,plen,PSTR("Enabled:<input type=checkbox value=1 name=ae "));
	if (alarmOn){
		plen=fill_tcp_data_p(buf,plen,PSTR("checked"));
	}
	plen=fill_tcp_data_p(buf,plen,PSTR(">\nName:   <input type=text name=n value=\""));
	plen=fill_tcp_data(buf,plen,myname);
	plen=fill_tcp_data_p(buf,plen,PSTR("\">\nSendto: ip=<input type=text name=di value="));
	mk_net_str(gStrbuf,udpsrvip,4,'.',10);
	plen=fill_tcp_data(buf,plen,gStrbuf);
	plen=fill_tcp_data_p(buf,plen,PSTR("> port=<input type=text name=dp size=4 value="));
	itoa(udpsrvport,gStrbuf,10);
	plen=fill_tcp_data(buf,plen,gStrbuf);
	plen=fill_tcp_data_p(buf,plen,PSTR("> gwip=<input type=text name=gi value="));
	mk_net_str(gStrbuf,gwip,4,'.',10);
	plen=fill_tcp_data(buf,plen,gStrbuf);
	plen=fill_tcp_data_p(buf,plen,PSTR(">\nPasswd: <input type=password name=pw>\n<input type=submit value=change></form>\n<hr>"));
	return(plen);
}

// main web page
uint16_t print_webpage(void)
{
	uint16_t plen;
	plen=http200ok();
	plen=fill_tcp_data_p(buf,plen,PSTR("<a href=/c>[config]</a> <a href=./>[refresh]</a>"));
	plen=fill_tcp_data_p(buf,plen,PSTR("<h2>Alarm: "));
	plen=fill_tcp_data(buf,plen,myname);
	plen=fill_tcp_data_p(buf,plen,PSTR("</h2><pre>\n"));
	plen=fill_tcp_data_p(buf,plen,PSTR("Last alarm:\n"));
	if (lastAlarm){
		if (gMin>59){
			itoa(gMin/60,gStrbuf,10); // convert integer to string
			plen=fill_tcp_data(buf,plen,gStrbuf);
			plen=fill_tcp_data_p(buf,plen,PSTR("hours and "));
		}
		itoa(gMin%60,gStrbuf,10); // convert integer to string
		plen=fill_tcp_data(buf,plen,gStrbuf);
		plen=fill_tcp_data_p(buf,plen,PSTR("min ago"));
		}else{
		plen=fill_tcp_data_p(buf,plen,PSTR("none in last 14 days"));
	}
	plen=fill_tcp_data_p(buf,plen,PSTR("\n</pre><hr>\n"));
	return(plen);
}

void data2eeprom(void)
{
	eeprom_write_byte((uint8_t *)40,19); // magic number
	eeprom_write_block((uint8_t *)gwip,(void *)41,sizeof(gwip));
	eeprom_write_block((uint8_t *)udpsrvip,(void *)45,sizeof(udpsrvip));
	eeprom_write_word((void *)49,udpsrvport);
	eeprom_write_byte((uint8_t *)51,alarmOn);
	eeprom_write_block((uint8_t *)myname,(void *)52,sizeof(myname));
}

void eeprom2data(void)
{
	if (eeprom_read_byte((uint8_t *)40) == 19){
		// ok magic number matches accept values
		eeprom_read_block((uint8_t *)gwip,(void *)41,sizeof(gwip));
		eeprom_read_block((uint8_t *)udpsrvip,(void *)45,sizeof(udpsrvip));
		udpsrvport=eeprom_read_word((void *)49);
		alarmOn=eeprom_read_byte((uint8_t *)51);
		eeprom_read_block((char *)myname,(void *)52,sizeof(myname));
	}
}

// analyse the url given
//                The string passed to this function will look like this:
//                ?s=1 HTTP/1.....
//                We start after the first slash ("/" already removed)
int8_t analyse_get_url(char *str)
{
	// the first slash:
	if (*str == 'c'){
		// configpage:
		gPlen=print_webpage_config();
		return(10);
	}
	if (*str == 'u'){
		if (find_key_val(str,gStrbuf,STR_BUFFER_SIZE,"pw")){
			urldecode(gStrbuf);
			if (verify_password(gStrbuf)){
				if (find_key_val(str,gStrbuf,STR_BUFFER_SIZE,"n")){
					urldecode(gStrbuf);
					gStrbuf[MYNAME_LEN]='\0';
					strcpy(myname,gStrbuf);
				}
				if (find_key_val(str,gStrbuf,STR_BUFFER_SIZE,"ae")){
					alarmOn=1;
					}else{
					alarmOn=0;
				}
				if (find_key_val(str,gStrbuf,STR_BUFFER_SIZE,"di")){
					urldecode(gStrbuf);
					if (parse_ip(udpsrvip,gStrbuf)!=0){
						return(-2);
					}
				}
				if (find_key_val(str,gStrbuf,STR_BUFFER_SIZE,"dp")){
					gStrbuf[4]='\0';
					udpsrvport=atoi(gStrbuf);
				}
				if (find_key_val(str,gStrbuf,STR_BUFFER_SIZE,"gi")){
					urldecode(gStrbuf);
					if (parse_ip(gwip,gStrbuf)!=0){
						return(-2);
					}
				}
				data2eeprom();
				gPlen=http200ok();
				gPlen=fill_tcp_data_p(buf,gPlen,PSTR("<a href=/>[home]</a>"));
				gPlen=fill_tcp_data_p(buf,gPlen,PSTR("<h2>OK</h2>"));
				return(10);
			}
		}
		return(-1);
	}
	return(0);
}

// called when TCNT2==OCR2A
// that is in 50Hz intervals
// This is used as a "clock" to store the data
ISR(TIMER2_COMPA_vect){
	cnt2step++;
	if (cnt2step>49){
		gSec++;
		cnt2step=0;
	}
	if (gSec>59){
		gSec=0;
		if (lastAlarm){
			gMin++;
			// 14 days is the limit:
			if (gMin>60*24*14){
				gMin=0;
				lastAlarm=0; // reset lastAlarm
			}
		}
	}
}

/* setup timer T2 as an interrupt generating time base.
* You must call once sei() in the main program */
void init_cnt2(void)
{
	cnt2step=0;
	PRR&=~(1<<PRTIM2); // write power reduction register to zero
	TIMSK2=(1<<OCIE2A); // compare match on OCR2A
	TCNT2=0;  // init counter
	OCR2A=244; // value to compare against
	TCCR2A=(1<<WGM21); // do not change any output pin, clear at compare match
	// divide clock by 1024: 12.5MHz/1024=12207.0313 Hz
	TCCR2B=(1<<CS22)|(1<<CS21)|(1<<CS20); // clock divider, start counter
	// 12207.0313 / 244= 50.0288
}


#if 0
// denis-m-tyurin: currently not used. the proto just polls the pin
ISR(INT1_vect)
{
	ALARM_LEDON;
}
#endif

// the __attribute__((unused)) is a gcc compiler directive to avoid warnings about unsed variables.
void arpresolver_result_callback(uint8_t *ip __attribute__((unused)),uint8_t transaction_number,uint8_t *mac){
	uint8_t i=0;
	if (transaction_number==TRANS_NUM_GWMAC){
		// copy mac address over:
		while(i<6){gwmac[i]=mac[i];i++;}
	}
}

int main(void){
	uint16_t dat_p;
	uint16_t contact_debounce=0;
	#define DEBOUNCECOUNT 0x1FFF
	int8_t cmd;
	uint8_t payloadlen=0;
	char cmdval;
	
	// set the clock speed to "no pre-scaler" (8MHz with internal osc or
	// full external speed)
	// set the clock prescaler. First write CLKPCE to enable setting of clock the
	// next four instructions.
	CLKPR=(1<<CLKPCE); // change enable
	CLKPR=0; // "no pre-scaler"
	_delay_loop_1(0); // 60us
	
	DDRC|= (1<<PC4) | (1<<PC5); // LED pins
	ETH_LEDOFF;
	ALARM_LEDOFF;
	
	/*initialize enc28j60*/
	enc28j60Init(mymac);
	enc28j60clkout(2); // change clkout from 6.25MHz to 12.5MHz
	_delay_loop_1(0); // 60us
	enc28j60PhyWrite(PHLCON,0x476);
	//
	eeprom2data();
	// time keeping
	init_cnt2();
	sei();

	// enable PD3 as input for the alarms system:
	DDRD&= ~(1<<PD3);
	
	//init the web server ethernet/ip layer:
	init_udp_or_www_server(mymac,myip);
	www_server_port(MYWWWPORT);
	
	//client_set_gwip(gwip);  // e.g internal IP of dsl router

	
#if 0
		// denis-m-tyurin: currently not used. the proto just polls the pin
		
		/* Configure interrupt for alarm pin (INT1)
		 * which is normally pulled up, therefore INT
		 * should fire on falling edge */
		EICRA |= (1 << ISC11);
		EIMSK |= (1 << INT1);
#endif	

	while(1){

		// handle ping and wait for a tcp/udp packet
		gPlen=enc28j60PacketReceive(BUFFER_SIZE, buf);
		buf[BUFFER_SIZE]='\0';

		if (contact_debounce==0 && bit_is_clear(PIND,PD3)==ALCONTACTCLOSE){
			// indicate an alarm and set the debounce counter
			// to not trigger multiple alarms at bouncing contacts
			if (alarmOn){
				contact_debounce=DEBOUNCECOUNT;
				gSec=0;
				gMin=0;
				lastAlarm=1;
				ALARM_LEDON;
			}
		}
		dat_p=packetloop_arp_icmp_tcp(buf,gPlen);

		if(dat_p==0){
			// no pending packet
			
			if (gPlen==0){
				if (enc28j60linkup() && 2==gw_arp_state)
				{
					ETH_LEDON;
				}
				else
				{
					ETH_LEDOFF;
				}
				if (contact_debounce==DEBOUNCECOUNT && 2==gw_arp_state){
					// send a real alarm
					strcpy(gStrbuf,"a=0:");
					strcat(gStrbuf,password);
					strcat(gStrbuf,", n=");
					strcat(gStrbuf,myname);
					strcat(gStrbuf,"\n");
					send_udp(buf,gStrbuf,strlen(gStrbuf),MYUDPPORT, udpsrvip, udpsrvport, gwmac);					
				}
				if (contact_debounce){
					contact_debounce--;
					}else{
					ALARM_LEDOFF;
				}
				
				// we are idle here - look up GW MAC here
				if (gw_arp_state==0)
				{
					// find the mac address of the gateway
					get_mac_with_arp(gwip,TRANS_NUM_GWMAC,&arpresolver_result_callback);
					gw_arp_state=1;
				}
				if (get_mac_with_arp_wait()==0 && gw_arp_state==1)
				{
					// done we have the mac address of the GW
					gw_arp_state=2;
				}
				
				continue;
			}
			// pending packet, check if udp otherwise continue
			goto UDP;
		}
		if (strncmp("GET ",(char *)&(buf[dat_p]),4)!=0){
			// head, post and other methods:
			//
			// for possible status codes see:
			// http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
			gPlen=http200ok();
			gPlen=fill_tcp_data_p(buf,gPlen,PSTR("<h1>200 OK</h1>"));
			goto SENDTCP;
		}
		// Cut the size for security reasons. If we are almost at the
		// end of the buffer then there is a zero but normally there is
		// a lot of room and we can cut down the processing time as
		// correct URLs should be short in our case. If dat_p is already
		// close to the end then the buffer is terminated already.
		if ((dat_p+100) < BUFFER_SIZE){
			buf[dat_p+100]='\0';
		}
		if (strncmp("/favicon.ico",(char *)&(buf[dat_p+4]),12)==0){
			// favicon:
			gPlen=fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 301 Moved Permanently\r\nLocation: "));
			gPlen=fill_tcp_data_p(buf,gPlen,PSTR("http://tuxgraphics.org/ico/a.ico"));
			gPlen=fill_tcp_data_p(buf,gPlen,PSTR("\r\n\r\nContent-Type: text/html\r\n\r\n"));
			gPlen=fill_tcp_data_p(buf,gPlen,PSTR("<h1>301 Moved Permanently</h1>\n"));
			goto SENDTCP;
		}
		// start after the first slash:
		cmd=analyse_get_url((char *)&(buf[dat_p+5]));
		// for possible status codes see:
		// http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
		if (cmd==-1){
			gPlen=fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 401 Unauthorized\r\nContent-Type: text/html\r\n\r\n<h1>401 Unauthorized</h1>"));
			goto SENDTCP;
		}
		if (cmd==-2){
			gPlen=http200ok();
			gPlen=fill_tcp_data_p(buf,gPlen,PSTR("<h1>ERROR in IP or port number</h1>"));
			goto SENDTCP;
		}
		if (cmd==10){
			// gPlen is already set
			goto SENDTCP;
		}
		// the main page:
		gPlen=print_webpage();
		//
		SENDTCP:
		www_server_reply(buf,gPlen); // send data
		continue;

		// tcp port www end
		// -------------------------------
		// udp start, we listen on udp port 1200=0x4B0
		UDP:
		// check if ip packets are for us:
		if(eth_type_is_ip_and_my_ip(buf,gPlen)==0){
			continue;
		}
		if (buf[IP_PROTO_P]==IP_PROTO_UDP_V&&buf[UDP_DST_PORT_H_P]==(MYUDPPORT>>8)&&buf[UDP_DST_PORT_L_P]==(MYUDPPORT&0xff)){
			payloadlen=buf[UDP_LEN_L_P]-UDP_HEADER_LEN;
			if (payloadlen>10){
				payloadlen=10;
			}
			// The start of the string is &(buf[UDP_DATA_P])
			if (payloadlen<3 || buf[UDP_DATA_P+1]!='='){
				continue; // do not send anything
				//strcpy(gStrbuf,"e=nocmd\n");
				//goto ANSWER;
			}
			cmdval=buf[UDP_DATA_P+2];
			// supported commands are:
			// s=?  // get status
			// n=?  // get system name
			// a=t  // trigger a test alarm
			if (buf[UDP_DATA_P]=='s'){
				if(cmdval=='?'){
					if (alarmOn==0){
						strcpy(gStrbuf,"a=off\n");
						goto ANSWER;
					}
					if (lastAlarm){
						strcpy(gStrbuf,"a=");
						itoa(gMin,&(gStrbuf[2]),10);
						strcat(gStrbuf,"\n");
						goto ANSWER;
					}
					strcpy(gStrbuf,"a=none\n");
					goto ANSWER;
				}
				strcpy(gStrbuf,"e=noarg\n");
				goto ANSWER;
			}
			// a=t:secret
			if (buf[UDP_DATA_P]=='a'){
				if(2==gw_arp_state && cmdval=='t' && buf[UDP_DATA_P+3]==':' && verify_password((char *)&(buf[UDP_DATA_P+4]))){
					// send a test alarm (an alarm the same way as if the real alarm triggered)
					strcpy(gStrbuf,"a=t:");
					strcat(gStrbuf,password);
					strcat(gStrbuf,", n=");
					strcat(gStrbuf,myname);
					strcat(gStrbuf,"\n");
					send_udp(buf,gStrbuf,strlen(gStrbuf),MYUDPPORT, udpsrvip, udpsrvport, gwmac);
					continue;
				}
			}
			if (buf[UDP_DATA_P]=='n'){
				cmdval=buf[UDP_DATA_P+2];
				if(cmdval=='?'){
					strcpy(gStrbuf,"n=");
					strcat(gStrbuf,myname);
					strcat(gStrbuf,"\n");
					goto ANSWER;
				}
			}
			strcpy(gStrbuf,"e=use: s=?,n=?,a=t:secret\n");
			ANSWER:
			make_udp_reply_from_request(buf,gStrbuf,strlen(gStrbuf),MYUDPPORT);
		}
	}
	return (0);
}