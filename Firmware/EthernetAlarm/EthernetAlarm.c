/*
 * EthernetAlarm.c
 *
 * Created: 03.05.2013 21:21:14
 *  Author: denis-m-tyurin
 */ 

#include <avr/io.h>
#include <avr/interrupt.h>
#include <avr/wdt.h>
#include <avr/sleep.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <avr/pgmspace.h>
#include <avr/eeprom.h>
#include "ip_arp_udp_tcp.h"
#include "websrv_help_functions.h"
#include "enc28j60.h"
#include "timeout.h"
#include "net.h"
#include "dhcp_client.h"

//---------------- start of modify lines --------
// please modify the following lines. mac and ip have to be unique
// in your network. You can not have the same numbers in
// two devices:
static uint8_t mymac[6] = {0x54,0x55,0x58,0x10,0x00,0x29};
// how did I get the mac addr? Translate the first 3 numbers into ascii is: TUX

// My own IP (DHCP will provide a value for it if enabled):
static uint8_t myip[4]={192,168,0,2};

// listen port for tcp/www:
#define MYWWWPORT 80
// the password string (only a-z,0-9,_ characters):
static char password[10]="sharedsec"; // must not be longer than 9 char
// MYNAME_LEN must be smaller than gStrbuf (below):
#define STR_BUFFER_SIZE 30
#define MYNAME_LEN STR_BUFFER_SIZE-14
static char myname[MYNAME_LEN+1]="ROOM_XXX";
// IP address of the alarm server to contact. The server we send the UDP to
static uint8_t udpsrvip[4] = {192,168,0,1};
static uint16_t udpsrvport=5151;

// Default gateway (DHCP will provide a value for it if enabled):
static uint8_t gwip[4]={192,168,0,1};

//---------------- end of modify lines --------
//
#define TRANS_NUM_GWMAC 1

typedef enum
{
	GW_ARP_STATE_NOT_INITIALIZED = 0,
	GW_ARP_STATE_IN_PROGRESS,
	GW_ARP_STATE_READY
	
} GW_ARP_STATES_T;

static uint8_t gwmac[6];
static uint8_t gw_arp_state=GW_ARP_STATE_NOT_INITIALIZED;
static uint16_t heartbeat_timeout_sec=10;
static volatile uint16_t heartbeat_counter=0; 
static uint8_t dhcpOn=1;

static uint8_t alarmInt=0; // Armed by interrupt from PD3 pin

#define BUFFER_SIZE 650
static uint8_t buf[BUFFER_SIZE+1];
static uint16_t gPlen;
static char gStrbuf[STR_BUFFER_SIZE+1];
static uint8_t alarmOn=1; // alarm system is on or off

static uint8_t lastAlarm=0; // indicates if we had an alarm or not
// timing:
static volatile uint8_t cnt2step=0;
static volatile uint8_t gSec=0;
static volatile uint8_t dhcp_tick_sec=0;
static volatile uint16_t gMin=0; // alarm time min

static volatile uint8_t flash_eth_led_ctr=0;
static volatile uint8_t flash_alarm_led_ctr=0;

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

uint16_t print_alarm_config(void)
{
	uint16_t plen;
	plen=http200ok();
	
	// Check if gatewy MAC look-up has been already done
	if (gw_arp_state==GW_ARP_STATE_IN_PROGRESS)
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
	plen=fill_tcp_data_p(buf,plen,PSTR(">\nPasswd: <input type=password name=pw>\n"));
	
	plen=fill_tcp_data_p(buf,plen,PSTR("<input type=submit value=change></form>\n<hr>"));
	return(plen);
}

uint16_t print_net_config(void)
{
	uint16_t plen;
	plen=http200ok();
	
	// Check if gatewy MAC look-up has been already done
	if (gw_arp_state==GW_ARP_STATE_IN_PROGRESS)
	{
		plen=fill_tcp_data_p(buf,plen,PSTR("waiting for GW MAC\n"));
		return(plen);
	}
	plen=fill_tcp_data_p(buf,plen,PSTR("<a href=/>[home]</a>"));
	plen=fill_tcp_data_p(buf,plen,PSTR("<h2>Network config</h2><pre>\n"));
	plen=fill_tcp_data_p(buf,plen,PSTR("<form action=/u method=get>"));
	plen=fill_tcp_data_p(buf,plen,PSTR("DHCP:<input type=checkbox value=1 name=dh "));
	if (dhcpOn){
		plen=fill_tcp_data_p(buf,plen,PSTR("checked"));
	}
	plen=fill_tcp_data_p(buf,plen,PSTR(">\nIP=<input type=text name=ip value="));
	mk_net_str(gStrbuf,myip,4,'.',10);
	plen=fill_tcp_data(buf,plen,gStrbuf);
	plen=fill_tcp_data_p(buf,plen,PSTR(">\ngwip=<input type=text name=gi value="));
	mk_net_str(gStrbuf,gwip,4,'.',10);
	plen=fill_tcp_data(buf,plen,gStrbuf);
	plen=fill_tcp_data_p(buf,plen,PSTR(">\nHeartbeat timeout=<input type=text name=hb value="));
	itoa(heartbeat_timeout_sec,gStrbuf,10);
	plen=fill_tcp_data(buf,plen,gStrbuf);
	plen=fill_tcp_data_p(buf,plen,PSTR(">\nPasswd: <input type=password name=pw>\n"));
	
	plen=fill_tcp_data_p(buf,plen,PSTR("<input type=submit value=change></form>\n<hr>"));
	return(plen);
}

// main web page
uint16_t print_webpage(void)
{
	uint16_t plen;
	plen=http200ok();
	plen=fill_tcp_data_p(buf,plen,PSTR("<a href=/c>[alarm config]</a> <a href=/n>[network config]</a> <a href=./>[refresh]</a>"));
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
	eeprom_write_word((void *)52,heartbeat_timeout_sec);
	eeprom_write_byte((uint8_t *)54,dhcpOn);
	eeprom_write_block((uint8_t *)myip,(void *)55,sizeof(myip));
	eeprom_write_block((uint8_t *)myname,(void *)59,sizeof(myname));	
}

void eeprom2data(void)
{
	if (eeprom_read_byte((uint8_t *)40) == 19){
		// ok magic number matches accept values
		eeprom_read_block((uint8_t *)gwip,(void *)41,sizeof(gwip));
		eeprom_read_block((uint8_t *)udpsrvip,(void *)45,sizeof(udpsrvip));
		udpsrvport=eeprom_read_word((void *)49);
		alarmOn=eeprom_read_byte((uint8_t *)51);
		heartbeat_timeout_sec=eeprom_read_word((void *)52);
		dhcpOn=eeprom_read_byte((uint8_t *)54);
		eeprom_read_block((uint8_t *)myip,(void *)55,sizeof(myip));
		eeprom_read_block((char *)myname,(void *)59,sizeof(myname));
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
		gPlen=print_alarm_config();
		return(10);
	}
	if (*str == 'n'){
		// configpage:
		gPlen=print_net_config();
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
				if (find_key_val(str,gStrbuf,STR_BUFFER_SIZE,"di")){
					urldecode(gStrbuf);
					if (parse_ip(udpsrvip,gStrbuf)!=0){
						return(-2);
					}					
					
					// we've found destip, which means this is update from the
					// alarm conf page (this is a mandatory field)
					// Check alarm check box here
					if (find_key_val(str,gStrbuf,STR_BUFFER_SIZE,"ae")){
						alarmOn=1;
					}else{
						alarmOn=0;
					}
				}
				if (find_key_val(str,gStrbuf,STR_BUFFER_SIZE,"dp")){
					gStrbuf[4]='\0';
					udpsrvport=atoi(gStrbuf);
				}
				if (find_key_val(str,gStrbuf,STR_BUFFER_SIZE,"hb")){
					gStrbuf[4]='\0';
					heartbeat_timeout_sec=atoi(gStrbuf);
					
					// we've found heartbeat, which means this is update from the
					// network conf page
					// Check dhcp check box here
					if (find_key_val(str,gStrbuf,STR_BUFFER_SIZE,"dh")){
						dhcpOn=1;
					}else{
						dhcpOn=0;
					}		
				}
				if (find_key_val(str,gStrbuf,STR_BUFFER_SIZE,"gi")){
					urldecode(gStrbuf);
					if (parse_ip(gwip,gStrbuf)!=0){
						return(-2);
					}
				}
				if (find_key_val(str,gStrbuf,STR_BUFFER_SIZE,"ip")){
					urldecode(gStrbuf);
					if (parse_ip(myip,gStrbuf)!=0){
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
		dhcp_tick_sec++;
		heartbeat_counter++;
		cnt2step=0;
	}
	
	if (dhcpOn && dhcp_tick_sec>5){
		dhcp_tick_sec=0;
		dhcp_6sec_tick();
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
	
	// Handle flashing status LEDs
	if (flash_eth_led_ctr > 0)
	{
		flash_eth_led_ctr--;
		if (flash_eth_led_ctr == 0)
		{
			ETH_LEDOFF;
		}
	}

	if (flash_alarm_led_ctr > 0)
	{
		flash_alarm_led_ctr--;
		if (flash_alarm_led_ctr == 0)
		{
			ALARM_LEDOFF;
		}
	}
}

ISR(INT1_vect)
{
	alarmInt = 1;
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
	uint8_t rval=0;
	
	// Disable wathcdog as it might be still enabled after reset
	wdt_disable();
	
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

	//init the web server ethernet/ip layer:
	init_udp_or_www_server(mymac,myip);
	www_server_port(MYWWWPORT);

	if (dhcpOn)
	{
		ALARM_LEDON;
		// DHCP handling. Get the initial IP    
		init_mac(mymac);
		while(rval==0)
		{
			gPlen=enc28j60PacketReceive(BUFFER_SIZE, buf);
			buf[BUFFER_SIZE]='\0';
			rval=packetloop_dhcp_initial_ip_assignment(buf,gPlen,mymac[5]);
		}
    
		// we have an IP:
		dhcp_get_my_ip(myip,NULL,gwip);
		client_ifconfig(myip,NULL);
    
		ALARM_LEDOFF;

		if (gwip[0]==0)
		{
			// we must have a gateway returned from the dhcp server
			// otherwise this code will not work
			ALARM_LEDON; // error
			ETH_LEDON;
			while(1); // stop here			
		}
	}
	
	// arm watchdog
	wdt_reset();
	wdt_enable(WDTO_2S);
		
	// a bit of power save stuff
	set_sleep_mode(SLEEP_MODE_PWR_SAVE); // use power save mode to keep T2 running (see datasheet)
	sleep_enable();
		
	// Disable clocks for unused peripherals
	PRR |= (1 << PRTWI) | (1 << PRTIM0) | (1 << PRTIM1) | (1 << PRUSART0) | (1 << PRADC);
	
	/* Configure interrupt for alarm pin (INT1)
	* which is normally pulled up, therefore INT
	* should fire on falling edge */
	EICRA |= (1 << ISC11);
	EIMSK |= (1 << INT1);

	while(1){
		
		// Kick watchdog, otherwise device will reset in 2 seconds
		wdt_reset();
		
		// handle ping and wait for a tcp packet
		gPlen=enc28j60PacketReceive(BUFFER_SIZE, buf);
		buf[BUFFER_SIZE]='\0';
		
		if (dhcpOn)
		{
			// DHCP renew IP:
			gPlen=packetloop_dhcp_renewhandler(buf,gPlen); // for this to work you have to call dhcp_6sec_tick() every 6 sec	
		}		
		
		dat_p=packetloop_arp_icmp_tcp(buf,gPlen);

		if(dat_p==0){
						
			// dat_p==0 && gPlen!=0 means UDP messages, which are just ignored
			
			if (gPlen==0){
				
				// no pending TCP packet
				
				if (!enc28j60linkup() || GW_ARP_STATE_READY != gw_arp_state)
				{
					flash_alarm_led_ctr=1;
					ALARM_LEDON;
				}

				if (contact_debounce==0 && alarmInt)
				{
					// indicate an alarm and set the debounce counter
					// to not trigger multiple alarms at bouncing contacts
					if (alarmOn)
					{
						contact_debounce=DEBOUNCECOUNT;
						gSec=0;
						gMin=0;
						lastAlarm=1;
						ALARM_LEDON;
		
						// Send alarm message to the server
						if (GW_ARP_STATE_READY==gw_arp_state)
						{
							// send a real alarm
							strcpy(gStrbuf,"a=0:");
							strcat(gStrbuf,password);
							strcat(gStrbuf,", n=");
							strcat(gStrbuf,myname);
							strcat(gStrbuf,"\n");
							send_udp(buf,gStrbuf,strlen(gStrbuf),udpsrvport, udpsrvip, udpsrvport, gwmac);
						}
					}
				}
				
				if (contact_debounce)
				{
					contact_debounce--;
					
					if (0 == contact_debounce)
					{
						ALARM_LEDOFF;
						alarmInt = 0; // Reset INT flag at the end of debouncing period to allow new alarm int-s
					}
				}				

				// we are idle here - look up GW MAC
				if (gw_arp_state==GW_ARP_STATE_NOT_INITIALIZED)
				{
					// find the mac address of the gateway
					get_mac_with_arp(gwip,TRANS_NUM_GWMAC,&arpresolver_result_callback);
					gw_arp_state=GW_ARP_STATE_IN_PROGRESS;
				}
				if (get_mac_with_arp_wait()==0 && gw_arp_state==GW_ARP_STATE_IN_PROGRESS)
				{
					// done we have the mac address of the GW
					gw_arp_state=GW_ARP_STATE_READY;
				}
				
				// Post heartbeat message if the counter expires
				if (heartbeat_counter >= heartbeat_timeout_sec && GW_ARP_STATE_READY==gw_arp_state)
				{
					heartbeat_counter = 0;
					snprintf(gStrbuf, STR_BUFFER_SIZE, "hb:n=%s\n", myname);
					send_udp(buf,gStrbuf,strlen(gStrbuf),udpsrvport, udpsrvip, udpsrvport, gwmac);
					ETH_LEDON;
					flash_eth_led_ctr=1;
				}
			}
			continue;
		}
		
		do {
			// Coming here means we've got valid TCP message
			if (strncmp("GET ",(char *)&(buf[dat_p]),4)!=0){
				// head, post and other methods:
				//
				// for possible status codes see:
				// http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
				gPlen=http200ok();
				gPlen=fill_tcp_data_p(buf,gPlen,PSTR("<h1>200 OK</h1>"));
				break;
			}
			// Cut the size for security reasons. If we are almost at the
			// end of the buffer then there is a zero but normally there is
			// a lot of room and we can cut down the processing time as
			// correct URLs should be short in our case. If dat_p is already
			// close to the end then the buffer is terminated already.
			if ((dat_p+100) < BUFFER_SIZE){
				buf[dat_p+100]='\0';
			}

			// start after the first slash:
			cmd=analyse_get_url((char *)&(buf[dat_p+5]));
			// for possible status codes see:
			// http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
			if (cmd==-1){
				gPlen=fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 401 Unauthorized\r\nContent-Type: text/html\r\n\r\n<h1>401 Unauthorized</h1>"));
				break;
			}
			if (cmd==-2){
				gPlen=http200ok();
				gPlen=fill_tcp_data_p(buf,gPlen,PSTR("<h1>ERROR in IP or port number</h1>"));
				break;
			}
			if (cmd==10){
				// gPlen is already set
				break;
			}
			// the main page:
			gPlen=print_webpage();
		} while (0);		
		www_server_reply(buf,gPlen); // send data
		
		// Going to sleep mode. MCU will wake up by timer2 interrupt
		sleep_cpu();
	}
	return (0);
}