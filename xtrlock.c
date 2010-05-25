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
#include <X11/keysym.h>
#include <xcb/xcb.h>
#include <xcb/xproto.h>
#include <xcb/xcb_keysyms.h>

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <pwd.h>
#include <unistd.h>
#include <string.h>

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

xcb_connection_t *display;
xcb_window_t window, root;
xcb_generic_error_t *xerr;
struct passwd *pw;


/*------------------------------------------------------------------*\
  pam-related stuff

  taken from pure-ftpd's authstuff, but you can see similar stuff
  in xlockmore, openssh and basicly all pam-related apps :)
  \*------------------------------------------------------------------*/

#define PAM_YN {							\
    if (PAM_error != 0 || pam_error != PAM_SUCCESS) {			\
      fprintf(stderr, "pam error: %s\n", pam_strerror(pam_handle, pam_error)); \
      pam_end(pam_handle, pam_error);					\
      return 0;								\
    }									\
  }

#define GET_MEM					\
  size += sizeof(struct pam_response);		\
  if ((reply = realloc(reply, size)) == NULL) { \
    PAM_error = 1;				\
    return PAM_CONV_ERR;			\
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

#define BUFSIZE 128

int main(int argc, char **argv){
  char rbuf[BUFSIZE]; /* shadow appears to suggest 127 a good value here */
  int rlen=0;
  long goodwill= INITIALGOODWILL, timeout= 0;
  xcb_cursor_t cursor;
  xcb_pixmap_t csr_source,csr_mask;

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

  display = xcb_connect(NULL,0);

  if (display==NULL) {
    fprintf(stderr,"xtrlock (version " PROGRAM_VERSION
	    "): cannot open display\n");
    exit(1);
  }

  xcb_screen_t *screen = xcb_setup_roots_iterator(xcb_get_setup(display)).data;
  uint32_t attrib = 1;
  window = xcb_generate_id(display);
  xcb_create_window(display, XCB_COPY_FROM_PARENT, window, screen->root,
		    0, 0, 1, 1, 0,
		    XCB_WINDOW_CLASS_INPUT_ONLY, XCB_COPY_FROM_PARENT,
		    XCB_CW_OVERRIDE_REDIRECT, &attrib);

  uint32_t mask = XCB_EVENT_MASK_KEY_PRESS | XCB_EVENT_MASK_KEY_RELEASE;
  xcb_change_window_attributes(display, window, XCB_CW_EVENT_MASK, &mask);

  // Cursor creation
  xcb_gcontext_t gc = xcb_generate_id(display);
  csr_source = xcb_generate_id(display);
  csr_mask = xcb_generate_id(display);
  xcb_create_gc(display, gc, root, 0, NULL);
  xcb_create_pixmap(display, 1, csr_source, window, lock_width, lock_height);
  xcb_create_pixmap(display, 1, csr_mask, window, mask_width, mask_height);
  xcb_put_image(display, XCB_IMAGE_FORMAT_XY_BITMAP, window, gc,
		lock_width, lock_height, 0, 0, 0, 8,
		lock_width*lock_height, lock_bits);
  xcb_put_image(display, XCB_IMAGE_FORMAT_XY_BITMAP, window, gc,
		mask_width, mask_height, 0, 0, 0, 8,
		mask_width*mask_height, mask_bits);

  xcb_alloc_named_color_cookie_t cookie;
  xcb_alloc_named_color_reply_t *csr_fg, *csr_bg;
  cookie = xcb_alloc_named_color(display, screen->default_colormap,
				 strlen("steelblue3"), "steelblue3");
  csr_bg = xcb_alloc_named_color_reply(display, cookie, &xerr);

  if(xerr || (!csr_bg)) {
    cookie = xcb_alloc_named_color(display, screen->default_colormap,
				   strlen("black"), "black");
    csr_bg = xcb_alloc_named_color_reply(display, cookie, &xerr);
  }

  cookie = xcb_alloc_named_color(display, screen->default_colormap,
				 strlen("gray25"), "gray25");
  csr_fg = xcb_alloc_named_color_reply(display, cookie, &xerr);

  if(xerr || (!csr_fg)) {
    cookie = xcb_alloc_named_color(display, screen->default_colormap,
				   strlen("white"), "white");
    csr_fg = xcb_alloc_named_color_reply(display, cookie, &xerr);
  }

  cursor = xcb_generate_id(display);
  xcb_create_cursor(display, cursor, csr_source, csr_mask,
		    csr_fg->exact_red, csr_fg->exact_green, csr_fg->exact_blue,
		    csr_bg->exact_red, csr_bg->exact_green, csr_bg->exact_blue,
		    lock_x_hot, lock_y_hot);

  
  xcb_map_window(display, window);

  // Grab keyboard and pointer
  xcb_grab_keyboard_cookie_t cookie_gk;
  xcb_grab_keyboard_reply_t *reply_gk;
  xcb_grab_pointer_cookie_t cookie_gp;
  xcb_grab_pointer_reply_t *reply_gp;
  cookie_gk = xcb_grab_keyboard(display, 0, window, XCB_CURRENT_TIME,
				XCB_GRAB_MODE_ASYNC, XCB_GRAB_MODE_ASYNC);
  cookie_gp = xcb_grab_pointer(display, 0, window, 0, // (KeyPressMask|KeyReleaseMask)&0
			       XCB_GRAB_MODE_ASYNC, XCB_GRAB_MODE_ASYNC,
			       XCB_WINDOW_NONE, cursor, XCB_CURRENT_TIME);
  reply_gk = xcb_grab_keyboard_reply(display, cookie_gk, &xerr);
  if (xerr || reply_gk->status != XCB_GRAB_STATUS_SUCCESS)
    exit(1);
  reply_gp = xcb_grab_pointer_reply(display, cookie_gp, &xerr);
  if (xerr || reply_gp->status != XCB_GRAB_STATUS_SUCCESS) {
    xcb_ungrab_keyboard(display, XCB_CURRENT_TIME);
    exit(1);
  }

  // Event loop
  xcb_generic_event_t *e;
  xcb_key_press_event_t *ev;
  xcb_key_symbols_t *keysyms = xcb_key_symbols_alloc(display);
  xcb_keysym_t ks;
  int looping = 1;

  while(looping && (e = xcb_wait_for_event(display)))
    {
      if(e->response_type != XCB_KEY_PRESS)
	continue;
      ev = (xcb_key_press_event_t *)e;
      ks = xcb_key_symbols_get_keysym(keysyms, ev->detail, 0);
      switch (ks) {
      case XK_Escape:
      case XK_Clear:
	rlen=0; break;
      case XK_Delete:
      case XK_BackSpace:
	if (rlen>0) rlen--; break;
      case XK_Linefeed:
      case XK_Return:
	if (rlen==0) break;
	rbuf[rlen]=0;
	if (passwordok(rbuf)) {
	  looping = 0; break; }
	xcb_bell(display, 0);
	rlen = 0;
	if (timeout) {
	  goodwill+= ev->time - timeout;
	  if (goodwill > MAXGOODWILL) {
	    goodwill= MAXGOODWILL;
	  }
	}
	timeout= -goodwill*GOODWILLPORTION;
	goodwill+= timeout;
	timeout+= ev->time + TIMEOUTPERATTEMPT;
	break;
      default:
	// if (clen != 1) 
	/* allow space for the trailing \0 */
	if (rlen < (BUFSIZE - 1)){
	  rbuf[rlen]=ks & 0xff; // would only work for latin1 keysyms
	  rlen++;
	}
	break;
      }

      free(e);
    }

  xcb_disconnect(display);
  exit(0);
}
