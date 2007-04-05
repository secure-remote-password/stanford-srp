/*
 * Copyright (c) Peter 'Luna' Runestig 1999, 2000 <peter@runestig.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY PETER RUNESTIG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _FWDXUTIL_H_
#define _FWDXUTIL_H_

void	fxwd_init(void);
void	fwdx_cleanup(void);
int	fwdx_open_channel(unsigned short channel);
void	fwdx_close_channel(unsigned short channel);
void	fwdx_forward(unsigned short channel, unsigned char *data, int len);
int	fwdx_redirect(unsigned short channel, unsigned char *data, int len);
void	fwdx_init_fd_set(fd_set *ibits);
int	fwdx_check_sockets(fd_set *ibits);
int	fwdx_get_screen_no(char *display);
void	fwdx_do_server_options(unsigned char *sp, int len);
int	fwdx_max_socket(void);

extern unsigned char *fwdx_sbdata;
extern int *fwdx_suspend;
extern int fwdx_sbdata_size;
extern int fwdx_enable_flag;

#endif
