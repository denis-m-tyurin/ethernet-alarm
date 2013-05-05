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
#include "ip_arp_udp_tcp.h"
#include "enc28j60.h"
#include "timeout.h"

#define ETH_LEDON PORTC|=(1<<PC5)
#define ETH_LEDOFF PORTC&=~(1<<PC5)

#define ALARM_LEDON PORTC|=(1<<PC4)
#define ALARM_LEDOFF PORTC&=~(1<<PC4)
// to test the state of the LED
#define ALARM_LEDISON PINC&(1<<PC4)


// please modify the following two lines. mac and ip have to be unique
// in your local area network. You can not have the same numbers in
// two devices:
// how did I get the mac addr? Translate the first 3 numbers into ascii is: TUX
static uint8_t mymac[6] = {0x54,0x55,0x58,0x10,0x00,0x29};
static uint8_t myip[4] = {192,168,0,17};

// server listen port for www
#define MYWWWPORT 80

// global packet buffer
#define BUFFER_SIZE 550
static uint8_t buf[BUFFER_SIZE+1];

uint16_t http200ok(void)
{
        return(fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nPragma: no-cache\r\n\r\n")));
}

// prepare the webpage by writing the data to the tcp send buffer
uint16_t print_webpage(uint8_t *buf)
{
        uint16_t plen;
        plen=http200ok();
        plen=fill_tcp_data_p(buf,plen,PSTR("<pre>"));
        plen=fill_tcp_data_p(buf,plen,PSTR("Hi!\nYour web server works great."));
		if (0 == ALARM_LEDISON)
		{
			plen=fill_tcp_data_p(buf,plen,PSTR("\n\nALARM IS OFf"));
		}
		else
		{
			plen=fill_tcp_data_p(buf,plen,PSTR("\n\nALARM IS ON"));
		}						
        plen=fill_tcp_data_p(buf,plen,PSTR("</pre>\n"));
        return(plen);
}

int main(void){
        uint16_t dat_p;
        
        // set the clock speed to 8MHz
        // set the clock prescaler. First write CLKPCE to enable setting of clock the
        // next four instructions.
        CLKPR=(1<<CLKPCE);
        CLKPR=0; // 8 MHZ
        _delay_loop_1(0); // 60us
        DDRC|= (1<<PC4) | (1<<PC5); // LED pins
        ETH_LEDOFF;
        
        //initialize the hardware driver for the enc28j60
        enc28j60Init(mymac);
        enc28j60clkout(2); // change clkout from 6.25MHz to 12.5MHz
        _delay_loop_1(0); // 60us
        enc28j60PhyWrite(PHLCON,0x476);
        
        //init the ethernet/ip layer:
        init_udp_or_www_server(mymac,myip);
        www_server_port(MYWWWPORT);
		
		/* Configure interrupt for alarm pin (INT1)
		 * which is normally pulled up, therefore INT
		 * should fire on falling edge */
		EICRA |= (1 << ISC11);
		EIMSK |= (1 << INT1);
		
		// Enable interrupts
		sei();
        while(1){
                // read packet, handle ping and wait for a tcp packet:
                dat_p=packetloop_arp_icmp_tcp(buf,enc28j60PacketReceive(BUFFER_SIZE, buf));

                // dat_p will be unequal to zero if there is a valid  http get
                if(dat_p==0){
                        // no http request
                        if (enc28j60linkup()){
                                ETH_LEDON;
                        }else{
                                ETH_LEDOFF;
                        }
                        continue;
                }
                // tcp port 80 begin
                if (strncmp("GET ",(char *)&(buf[dat_p]),4)!=0){
                        // head, post and other methods:
                        dat_p=http200ok();
                        dat_p=fill_tcp_data_p(buf,dat_p,PSTR("<h1>200 OK</h1>"));
                        goto SENDTCP;
                }
                // just one web page in the "root directory" of the web server
                if (strncmp("/ ",(char *)&(buf[dat_p+4]),2)==0){
                        dat_p=print_webpage(buf);
                        goto SENDTCP;
                }else{
                        dat_p=fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 401 Unauthorized\r\nContent-Type: text/html\r\n\r\n<h1>401 Unauthorized</h1>"));
                        goto SENDTCP;
                }
SENDTCP:
                www_server_reply(buf,dat_p); // send web page data
                // tcp port 80 end
        }
        return (0);
}

ISR(INT1_vect)
{
	ALARM_LEDON;
}
