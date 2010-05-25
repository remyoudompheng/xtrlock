/*------------------------------------------------------------------*\
   xtrlock.c

  X Transparent Lock
 
  Copyright (C)1993,1994 Ian Jackson
 
  This is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2, or (at your option)
  any later version.
 
  This is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
 
\*------------------------------------------------------------------*/

/*------------------------------------------------------------------*\
\*------------------------------------------------------------------*/
#include <X11/X.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <X11/Xos.h>

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <string.h>
#include <crypt.h>
#include <unistd.h>
#include <math.h>
#include <ctype.h>
#include <values.h>

#define PROGRAM_VERSION "2.0"

#include <security/pam_appl.h>

/*----------------------------------------------*\
\*----------------------------------------------*/

#include "lock.bitmap"
#include "mask.bitmap"

/*------------------------------------------------------------------*\
    globals
\*------------------------------------------------------------------*/

#define TIMEOUTPERATTEMPT 30000
#define MAXGOODWILL  (TIMEOUTPERATTEMPT*5)
#define INITIALGOODWILL MAXGOODWILL
#define GOODWILLPORTION 0.3

Display *display;
Window window, root;
struct passwd *pw;


/*------------------------------------------------------------------*\
    pam-related stuff
    
    taken from pure-ftpd's authstuff, but you can see similar stuff
    in xlockmore, openssh and basicly all pam-related apps :)
\*------------------------------------------------------------------*/

#define PAM_YN { \
    if (PAM_error != 0 || pam_error != PAM_SUCCESS) { \
        fprintf(stderr, "pam error: %s\n", pam_strerror(pam_handle, pam_error)); \
        pam_end(pam_handle, pam_error); \
        return 0;\
    } \
}

#define GET_MEM \
    size += sizeof(struct pam_response); \
    if ((reply = realloc(reply, size)) == NULL) { \
        PAM_error = 1; \
        return PAM_CONV_ERR; \
    }

static const char* PAM_username = NULL;
static const char* PAM_password = NULL;
static int PAM_error = 0;
static int pam_error = PAM_SUCCESS;

static int PAM_conv(int num_msg, const struct pam_message **msgs,
	              struct pam_response **resp, void *appdata_ptr) {

    int count = 0;
    unsigned int replies = 0U;
    struct pam_response *reply = NULL;
    size_t size = (size_t) 0U;

    (void) appdata_ptr;
    *resp = NULL;
    for (count = 0; count < num_msg; count++) {
        switch (msgs[count]->msg_style) {
        case PAM_PROMPT_ECHO_ON:
            GET_MEM;
            memset(&reply[replies], 0, sizeof reply[replies]);
            if ((reply[replies].resp = strdup(PAM_username)) == NULL) {
#ifdef PAM_BUF_ERR
                reply[replies].resp_retcode = PAM_BUF_ERR;
#endif
                PAM_error = 1;
                return PAM_CONV_ERR;
            }
            reply[replies++].resp_retcode = PAM_SUCCESS;
            /* PAM frees resp */
            break;
        case PAM_PROMPT_ECHO_OFF:
            GET_MEM;
            memset(&reply[replies], 0, sizeof reply[replies]);
            if ((reply[replies].resp = strdup(PAM_password)) == NULL) {
#ifdef PAM_BUF_ERR
                reply[replies].resp_retcode = PAM_BUF_ERR;
#endif
                PAM_error = 1;
                return PAM_CONV_ERR;
            }
            reply[replies++].resp_retcode = PAM_SUCCESS;
            /* PAM frees resp */
            break;
        case PAM_TEXT_INFO:
            /* ignore it... */
            break;
        case PAM_ERROR_MSG:
        default:
            /* Must be an error of some sort... */
            free(reply);
            PAM_error = 1;
            return PAM_CONV_ERR;
        }
    }
    *resp = reply;
    return PAM_SUCCESS;
}

static struct pam_conv PAM_conversation = {
    &PAM_conv, NULL
};

/*------------------------------------------------------------------*\
\*------------------------------------------------------------------*/

int passwordok(const char *s) {
     pam_handle_t* pam_handle = NULL;
     PAM_username = pw->pw_name;
     PAM_password = s;
     pam_error = pam_start("xlock", PAM_username, &PAM_conversation, &pam_handle);
     PAM_YN;
     pam_error = pam_authenticate(pam_handle, 0);
     PAM_YN;
     pam_error = pam_end(pam_handle, pam_error);
     PAM_YN;
     return 1;
}

int main(int argc, char **argv){
  XEvent ev;
  KeySym ks;
  char cbuf[10], rbuf[128]; /* shadow appears to suggest 127 a good value here */
  int clen, rlen=0;
  long goodwill= INITIALGOODWILL, timeout= 0;
  XSetWindowAttributes attrib;
  Cursor cursor;
  Pixmap csr_source,csr_mask;
  XColor csr_fg, csr_bg, dummy;
  int ret;

  if (argc != 1) {
        fprintf(stderr, "xtrlock (version " PROGRAM_VERSION 
		"): no arguments allowed\n");
    exit(1);
  }
  
    errno = 0;
    pw = getpwuid(getuid());
    if (!pw) {
        perror("password entry for uid not found");
        exit(1);
    }

  /* logically, if we need to do the following then the same 
     applies to being installed setgid shadow.  
     we do this first, because of a bug in linux. --jdamery */ 
  setgid(getgid());
  /* we can be installed setuid root to support shadow passwords,
     and we don't need root privileges any longer.  --marekm */
  setuid(getuid());
  
  display= XOpenDisplay(0);

  if (display==NULL) {
    fprintf(stderr,"xtrlock (version " PROGRAM_VERSION
	    "): cannot open display\n");
    exit(1);
  }

  attrib.override_redirect= True;
  window= XCreateWindow(display,DefaultRootWindow(display),
                        0,0,1,1,0,CopyFromParent,InputOnly,CopyFromParent,
                        CWOverrideRedirect,&attrib);
                        
  XSelectInput(display,window,KeyPressMask|KeyReleaseMask);

  csr_source= XCreateBitmapFromData(display,window,lock_bits,lock_width,lock_height);
  csr_mask= XCreateBitmapFromData(display,window,mask_bits,mask_width,mask_height);

  ret = XAllocNamedColor(display,
                        DefaultColormap(display, DefaultScreen(display)),
                        "steelblue3",
                        &dummy, &csr_bg);
  if (ret==0)
    XAllocNamedColor(display,
                    DefaultColormap(display, DefaultScreen(display)),
                    "black",
                    &dummy, &csr_bg);

  ret = XAllocNamedColor(display,
                        DefaultColormap(display,DefaultScreen(display)),
                        "grey25",
                        &dummy, &csr_fg);
  if (ret==0)
    XAllocNamedColor(display,
                    DefaultColormap(display, DefaultScreen(display)),
                    "white",
                    &dummy, &csr_bg);



  cursor= XCreatePixmapCursor(display,csr_source,csr_mask,&csr_fg,&csr_bg,
                              lock_x_hot,lock_y_hot);

  XMapWindow(display,window);
  if (XGrabKeyboard(display,window,False,GrabModeAsync,GrabModeAsync,
		    CurrentTime)!=GrabSuccess) {
    exit(1);
  }
  if (XGrabPointer(display,window,False,(KeyPressMask|KeyReleaseMask)&0,
               GrabModeAsync,GrabModeAsync,None,
               cursor,CurrentTime)!=GrabSuccess) {
    XUngrabKeyboard(display,CurrentTime);
    exit(1);
  }

  for (;;) {
    XNextEvent(display,&ev);
    switch (ev.type) {
    case KeyPress:
      if (ev.xkey.time < timeout) { XBell(display,0); break; }
      clen= XLookupString(&ev.xkey,cbuf,9,&ks,0);
      switch (ks) {
      case XK_Escape: case XK_Clear:
        rlen=0; break;
      case XK_Delete: case XK_BackSpace:
        if (rlen>0) rlen--;
        break;
      case XK_Linefeed: case XK_Return:
        if (rlen==0) break;
        rbuf[rlen]=0;
        if (passwordok(rbuf)) goto loop_x;
        XBell(display,0);
        rlen= 0;
        if (timeout) {
          goodwill+= ev.xkey.time - timeout;
          if (goodwill > MAXGOODWILL) {
            goodwill= MAXGOODWILL;
          }
        }
        timeout= -goodwill*GOODWILLPORTION;
        goodwill+= timeout;
        timeout+= ev.xkey.time + TIMEOUTPERATTEMPT;
        break;
      default:
        if (clen != 1) break;
        /* allow space for the trailing \0 */
	if (rlen < (sizeof(rbuf) - 1)){
	  rbuf[rlen]=cbuf[0];
	  rlen++;
	}
        break;
      }
      break;
    default:
      break;
    }
  }
 loop_x:
  exit(0);
}
