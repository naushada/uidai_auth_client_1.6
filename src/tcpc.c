/* mode: c; c-basic-offset: 2
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/*
================================================================================
Date        Author                        Remarks
--------------------------------------------------------------------------------
05/15/2016  naushad.dln@gmail.com         Inital Draft

------------------------------------------------------------------------------*/

#ifndef __TCPC_C__
#define __TCPC_C__

#include "common.h"
#include "tcpc.h"

/**
 * This function is used to create the TCP socket of INTERNET TYPE
 *
 * @author    Mohd Naushad Ahmed
 * @version   1.0
 * @param     none
 * @return    Newly created file descriptor upon success or an error upon
 *            failure.
 */
int tcp_socket(void)
{
  int sock_fd = -1;

  sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  return(sock_fd);
}/* tcp_socket */


int tcp_connect(int conn_fd, const char* ip, unsigned short port)
{
  struct sockaddr_in remote_addr;

  memset((void*)&remote_addr, 0, sizeof(remote_addr));

  remote_addr.sin_family        = AF_INET;
  remote_addr.sin_addr.s_addr   = inet_addr(ip);
  remote_addr.sin_port          = htons(port);

  memset((void *)&remote_addr.sin_zero,
         0,
         (size_t)sizeof(remote_addr.sin_zero));
 return(connect(conn_fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr))); 

}/* tcp_connect */


/**
 * This function makes the file descriptor addressable by binding
 * file descriptor to IP address and port.
 *
 * @author    Mohd Naushad Ahmed
 * @version   1.0
 * @param     IP Address to be bind and this shall be IPv4.
 * @param     TCP port on which IP Address to associated with.
 * @param     TCP file descriptor.
 * @return    return code of bind function.
 */
int tcp_bind(const char *ip_address, int ip_port, int sock_fd)
{
  int rc = -1;
  struct sockaddr_in self_addr;

  memset((void*)&self_addr,0,sizeof(self_addr));

  self_addr.sin_family        = AF_INET;
  self_addr.sin_addr.s_addr   = inet_addr(ip_address);
  self_addr.sin_port          = htons(ip_port);

  memset((void *)&self_addr.sin_zero,
         0,
         (size_t)sizeof(self_addr.sin_zero));

  rc =  bind((int)sock_fd,
             (struct sockaddr *)&self_addr,
             (size_t)sizeof(self_addr));

  return(rc);
}/* tcp_bind */


/**
 * This function sets the back log of simultaneous connection of the adderssed
 * file descriptor.
 *
 * @author    Mohd Naushad Ahmed
 * @version   1.0
 * @param     file descriptor
 * @param     TCP connection back log (queue size).
 * @return    return code of listen function.
 */
int tcp_listen(int sock_fd, int back_log)
{
  int rc = -1;
  rc = listen (sock_fd,back_log);

  return(rc);
}/* tcp_listen */


/**
 * This function is used to accept a new cllient connection and updates the
 * max_fd. Also stores the IP Address of the TCP client and marks the fd_state 
 * as FD_STATE_CONNECTED.
 *
 * @author    Mohd Naushad Ahmed
 * @version   1.0
 * @param     listen file descriptor on which TCP client can connect.
 * @return    returns the newly connected file descriptor.
 */
int tcp_accept(int listen_fd)
{
  int       sock_fd = -1;
  struct    sockaddr_in addr;
  socklen_t addr_len;
  
  sock_fd =  accept (listen_fd,
                     (struct sockaddr *)&addr,
                     (socklen_t *)&addr_len);
  
  return(sock_fd);
}/* tcp_accept */


/**
 *  This function is used to read the incoming data from TCP client for given 
 *  file descriptor.
 *
 * @author    Mohd Naushad Ahmed
 * @version   1.0
 * @param     file descriptor on which data has arrived.
 * @param     pointer to char data buffer in which read data to be stored.
 * @param     maximum data buffer length.
 * @return    actual number of bytes read.
 */
int tcp_read(int sock_fd, char *buffer, int buffer_len, int flag)
{
  return (recv (sock_fd, (void *)buffer, buffer_len, (int)flag) );
} /* tcp_read */


/**
 * This function is used to send data on TCP connection for given 
 * file descriptor.
 *
 * @author    Mohd Naushad Ahmed
 * @version   1.0
 * @param     file descriptor on which data to be writen.
 * @param     data buffer to be sent.
 * @param     actual data length to be sent over TCP connection.
 * @return    bytes sent to TCP client.
 */
int tcp_write(int sock_fd, char *data_buffer, int data_len, int flag)
{
  int sent_data = 0;
  char *data_buff_ptr = NULL;
  int  offset = 0;

  data_buff_ptr = (char *) malloc(data_len);
  if (data_buff_ptr == NULL)
  {
    fprintf(stderr,"Buffer Allocation Failed for length %d\n",data_len);
  }
	memset((void *)data_buff_ptr, 0, data_len);
  memcpy(data_buff_ptr, data_buffer, data_len); 
  do
	{
    sent_data = send(sock_fd, (char *)&data_buff_ptr[offset], data_len, (int)0);
		fprintf(stderr, "Data Sent are %d\n", sent_data);
		offset += sent_data;
		/*Remaining Data to be sent*/
		data_len -=sent_data;

	}while(data_len !=0);

  free(data_buff_ptr);
  return(sent_data);
}/* tcp_write */

int tcp_display_fdlist(int *fd_list, int fd_list_length)
{
  int idx = 0;
  
	for(idx =0; idx <fd_list_length; idx++)
	{
    fprintf(stderr, "fd_list[%d] %d ", idx, fd_list[idx]);		
	}	
}/*tcp_display_fdlist*/

int tcp_rearrange_fdlist(int *fd_list, int *fd_list_length)
{
  int idx = 0;
  int idx_in = 0;
  int tmp_fd_list[256];

	memset((void *)tmp_fd_list, 0, sizeof(tmp_fd_list));
  

  for(idx = 0; idx < *fd_list_length; idx++)
	{
	  if(fd_list[idx] > 0)
		{
	    tmp_fd_list[idx_in++] = fd_list[idx];		
		}	
	}

	memset((void *)fd_list, 0, (sizeof(int) * (*fd_list_length)));
  memcpy((void *)fd_list, tmp_fd_list, (idx_in * sizeof(int)));
  *fd_list_length = idx_in;

  return(idx_in);

}/*tcp_rearrange_fdlist*/


int tcp_get_ip_address(char * hostname , char* ip)
{
  struct hostent *he;
  struct in_addr **addr_list;
  int i;
        
  if((he = gethostbyname(hostname)) == NULL) 
  {
    // get the host info
    fprintf(stderr, "gethostbyname is returning an error\n");
    herror("gethostbyname");
    return (-1);
  }
 
  addr_list = (struct in_addr **) he->h_addr_list;
     
  for(i = 0; addr_list[i] != NULL; i++) 
  {
    strcpy(ip ,inet_ntoa(*addr_list[i]));
    fprintf(stderr, "IP Address is %s\n", ip);
    return 0;
  }
  return (-2);
}/*tcp_get_ip_address*/





#endif
