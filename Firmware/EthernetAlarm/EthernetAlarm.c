/*
 * EthernetAlarm.c
 *
 * Created: 03.05.2013 21:21:14
 *  Author: denis-m-tyurin
 */ 


#include <avr/io.h>
#include <util/delay.h>

int main(void)
{
	DDRC = (1<<PC4) | (1<<PC5);
	PORTC = (1<<PC4);
    while(1)
    {
        PORTC = (1<<PC4);
		_delay_ms(1000);
		PORTC = (1<<PC5);
		_delay_ms(1000);
    }
}