#ifndef TPL_H
#define TPL_H

#include <libowfat/iob.h>
#include <libowfat/str.h>
#include <libowfat/case.h>
#include <libowfat/scan.h>
#include <libowfat/fmt.h>
#include "http.h"
#include "persistence.h"
#include "print.h"
#include "params.h"
#include "session.h"


//void print_page_header(http_context *http, const char *title);
#define print_page_header(http, ...) \
	do { \
		PRINT(S("<!DOCTYPE html>" \
		        "<html>" \
		          "<head>" \
              "<link rel=\"stylesheet\" media=\"screen\" href=\"https://fontlibrary.org/face/inconsolata\" type=\"text/css\"/> " \
		            "<title>"), \
		            __VA_ARGS__, S( \
		            "</title>" \
		            "<style>")); \
		write_page_css(http); \
		PRINT(S(    "</style>" \
		          "</head>" \
		          "<body>")); \
	} while(0)

void write_page_css(http_context *http);

enum {
	WRITE_REPLY_AS_MOD   = 1 << 0,
	WRITE_REPLY_AS_ADMIN = 1 << 1
};

void print_reply_form(http_context *http, struct board *board, struct thread *thread, struct captcha *captcha, struct user *user);
void print_mod_bar(http_context *http, int ismod);
void print_page_footer(http_context *http);
void print_board_bar(http_context *http);
void print_top_bar(http_context *http, struct user *user, const char *url);
void print_bottom_bar(http_context *http);

void print_upload(http_context *http, struct upload *upload);

enum {
	WRITE_POST_IP         = 1 << 0,
	WRITE_POST_USER_AGENT = 1 << 1
};

void print_post(http_context *http, struct post *post, int absolute_url, int flags);
void print_post_url(http_context *http, struct post *post, int absolute);
void print_post_url2(http_context *http, struct board *board, struct thread *thread, struct post *post, int absolute);
void abbreviate_filename(char *buffer, size_t max_length);
void abbreviate_filename_px(char *buffer, size_t max_width);
size_t estimate_width(const char *buffer);



#endif // TPL_H
