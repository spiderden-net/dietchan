#include "import.h"

#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <libowfat/buffer.h>
#include <libowfat/scan.h>
#include <libowfat/textcode.h>
#include <libowfat/array.h>
#include <libowfat/str.h>
#include <libowfat/array.h>
#include "util.h"
#include "persistence.h"

enum json_token_type {
	TOK_ERROR,
	TOK_EOF,
	TOK_OBJ_BEGIN,
	TOK_OBJ_END,
	TOK_ARRAY_BEGIN,
	TOK_ARRAY_END,
	TOK_COLON,
	TOK_NUMBER,
	TOK_STRING,
};

struct json_token {
	enum json_token_type type;
	char  *string;
	int64 number;
};

static array buf = {0};
static size_t buf_len = 0;
static size_t off=0;
static int fd=0;

void free_token(struct json_token *token)
{
	if (token->string) {
		free(token->string);
		token->string = 0;
	}
}

struct json_token json_get_token()
{
	struct json_token token = {0};

	char tmp[4096];
	char *b;
	ssize_t bytes_read;

	while (1) {
		b = array_start(&buf);

		if (off >= buf_len)
			goto read_more;

		off += scan_whiteskip(&b[off]);
		if (off >= buf_len)
			goto read_more;

		switch (b[off]) {
			case '{':
				token.type = TOK_OBJ_BEGIN;
				++off;
				return token;
			case '}':
				token.type = TOK_OBJ_END;
				++off;
				return token;
			case '[':
				token.type = TOK_ARRAY_BEGIN;
				++off;
				return token;
			case ']':
				token.type = TOK_ARRAY_END;
				++off;
				return token;
			case '"': {
				token.type = TOK_STRING;
				size_t dest_len=0;
				size_t scanned = scan_json_str(&b[off+1], 0, &dest_len) + 1;
				if (off+scanned >= buf_len)
					goto read_more;
				token.string = malloc(scanned+1);
				token.string[scan_json_str(&b[off+1], token.string, &dest_len)] = '\0';
				off += scanned;
				return token;
			}
			case ',':
				off += 1;
				continue;
			case ':':
				off += 1;
				token.type = TOK_COLON;
				return token;
			case '-': case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9': {
				token.type = TOK_NUMBER;
				size_t scanned = scan_int64(&b[off], &token.number);
				if ((scanned==0) || off+scanned >= buf_len)
					goto read_more;
				off += scanned;
				return token;
			}
			case '\0':
				token.type = TOK_EOF;
				return token;
			default:
				token.type = TOK_ERROR;
				return token;
		}

read_more:

		bytes_read = read(fd, tmp, sizeof(buf));
		if (bytes_read < 0) {
			token.type = TOK_ERROR;
			return token;
		}

		if (buf_len>0) // Remove added \0 byte
			array_truncate(&buf, 1, buf_len);
		array_chop_beginning(&buf, off);
		off = 0;
		array_catb(&buf, tmp, bytes_read);

		// Add an additional zero when EOF
		if (bytes_read == 0)
			array_cat0(&buf);

		buf_len = array_bytes(&buf);
		array_cat0(&buf);
	}
}

static int parse_array(int (*foreach)(void *extra), void *extra)
{
	while (1) {
		struct json_token token = json_get_token();
		free_token(&token);
		if (token.type == TOK_ARRAY_END)
			return 0;
		if (token.type != TOK_OBJ_BEGIN)
			return -1;

		if (foreach(extra) == -1)
			return -1;
	}
}

static void json_skip_structure(const struct json_token *token);

static void json_skip_object()
{
	while (1) {
		struct json_token token = json_get_token();
		if (token.type == TOK_EOF || token.type == TOK_OBJ_END)
			return;
		json_skip_structure(&token);
	}
}

static void json_skip_array()
{
	while (1) {
		struct json_token token = json_get_token();
		if (token.type == TOK_EOF || token.type == TOK_ARRAY_END)
			return;
		json_skip_structure(&token);
	}
}

static void json_skip_structure(const struct json_token *token)
{
	switch (token->type) {
		case TOK_EOF:
			return;
		case TOK_ARRAY_BEGIN:
			json_skip_array();
			break;
		case TOK_OBJ_BEGIN:
			json_skip_object();
			break;
	}
}

#define FAIL() do { printf("Error\n"); exit(-1); } while (0)

#define EXPECT(token_type) \
	{ \
		struct json_token tok = json_get_token(); \
		free_token(&tok); \
		if (tok.type != token_type) { \
			printf("parse error: %d\n", __LINE__); \
			return -1; \
		} \
	}

#define EXPECT2(token_type, token) \
	{ \
		*(token) = json_get_token(); \
		if ((token)->type != token_type) { \
			printf("parse error: %d\n", __LINE__); \
			free_token(token); \
			return -1; \
		} \
	}

static int parse_upload(struct post *post)
{
	struct upload *upload = upload_new();
	struct upload *prev = post_last_upload(post);
	if (!post_first_upload(post))
		post_set_first_upload(post, upload);
	post_set_last_upload(post, upload);

	upload_set_prev_upload(upload, prev);
	if (prev)
		upload_set_next_upload(prev, upload);

	while (1) {
		struct json_token token = json_get_token();
		if (token.type  == TOK_OBJ_END)
			return 0;
		if (token.type != TOK_STRING) {
			free_token(&token);
			return -1;
		}

		EXPECT(TOK_COLON);

		struct json_token val = {0};
		if (str_equal(token.string, "file")) {
			EXPECT2(TOK_STRING, &val);
			upload_set_file(upload, val.string);
		} else if (str_equal(token.string, "thumbnail")) {
			EXPECT2(TOK_STRING, &val);
			upload_set_thumbnail(upload, val.string);
		} else if (str_equal(token.string, "original_name")) {
			EXPECT2(TOK_STRING, &val);
			upload_set_original_name(upload, val.string);
		} else if (str_equal(token.string, "mime_type")) {
			EXPECT2(TOK_STRING, &val);
			upload_set_mime_type(upload, val.string);
		} else if (str_equal(token.string, "size")) {
			EXPECT2(TOK_NUMBER, &val);
			upload_set_size(upload, val.number);
		} else if (str_equal(token.string, "width")) {
			EXPECT2(TOK_NUMBER, &val);
			upload_set_width(upload, val.number);
		} else if (str_equal(token.string, "height")) {
			EXPECT2(TOK_NUMBER, &val);
			upload_set_height(upload, val.number);
		} else if (str_equal(token.string, "duration")) {
			EXPECT2(TOK_NUMBER, &val);
			upload_set_duration(upload, val.number);
		} else if (str_equal(token.string, "state")) {
			EXPECT2(TOK_NUMBER, &val);
			upload_set_state(upload, val.number);
		} else {
			val = json_get_token();
			json_skip_structure(&val);
		}
		free_token(&val);

		free_token(&token);
	}
}

static int parse_post(struct thread *thread)
{
	struct post *post = post_new();
	struct post *prev = thread_last_post(thread);
	post_set_thread(post, thread);
	if (!thread_first_post(thread))
		thread_set_first_post(thread, post);
	thread_set_last_post(thread, post);

	post_set_prev_post(post, prev);
	if (prev)
		post_set_next_post(prev, post);

	uint64 post_count = thread_post_count(thread);
	++post_count;
	thread_set_post_count(thread, post_count);


	while (1) {
		struct json_token token = json_get_token();
		if (token.type  == TOK_OBJ_END)
			return 0;
		if (token.type != TOK_STRING) {
			free_token(&token);
			return -1;
		}

		EXPECT(TOK_COLON);

		struct json_token val = {0};
		if (str_equal(token.string, "id")) {
			EXPECT2(TOK_NUMBER, &val);
			post_set_id(post, val.number);

			uint64 post_counter = master_post_counter(master);
			if (post_id(post) > post_counter)
				post_counter = post_id(post);
			master_set_post_counter(master, post_counter);
			db_hashmap_insert(&post_tbl, &post_id(post), post);
		} else if (str_equal(token.string, "ip")) {
			EXPECT2(TOK_STRING, &val);
			struct ip ip = {0};
			scan_ip(val.string, &ip);
			post_set_ip(post, ip);
		} else if (str_equal(token.string, "x_real_ip")) {
			EXPECT2(TOK_STRING, &val);
			struct ip ip = {0};
			scan_ip(val.string, &ip);
			post_set_x_real_ip(post, ip);
		} else if (str_equal(token.string, "x_forwarded_for")) {
			EXPECT(TOK_ARRAY_BEGIN);
			array ips = {0};
			size_t count=0;
			while (1) {
				val = json_get_token();
				if (val.type == TOK_ARRAY_END)
					break;
				if (val.type != TOK_STRING) {
					free_token(&val);
					return -1;
				}
				struct ip *ip = array_allocate(&ips, sizeof(struct ip), count++);
				scan_ip(val.string, ip);
				free_token(&val);
			}

			if (count > 0) {
				struct ip *pips = db_alloc0(count*sizeof(struct ip));
				memcpy(pips, array_start(&ips), count*sizeof(struct ip));
				db_invalidate(db, pips);
				post_set_x_forwarded_for(post, pips);
				post_set_x_forwarded_for_count(post, count);
			}

			array_reset(&ips);
		} else if (str_equal(token.string, "useragent")) {
			EXPECT2(TOK_STRING, &val);
			post_set_useragent(post, val.string);
		} else if (str_equal(token.string, "user_role")) {
			EXPECT2(TOK_NUMBER, &val);
			post_set_user_role(post, val.number);
		} else if (str_equal(token.string, "username")) {
			EXPECT2(TOK_STRING, &val);
			post_set_username(post, val.string);
		} else if (str_equal(token.string, "password")) {
			EXPECT2(TOK_STRING, &val);
			post_set_password(post, val.string);
		} else if (str_equal(token.string, "sage")) {
			EXPECT2(TOK_NUMBER, &val);
			post_set_sage(post, val.number);
		} else if (str_equal(token.string, "banned")) {
			EXPECT2(TOK_NUMBER, &val);
			post_set_banned(post, val.number);
		} else if (str_equal(token.string, "reported")) {
			EXPECT2(TOK_NUMBER, &val);
			post_set_reported(post, val.number);
		} else if (str_equal(token.string, "ban_message")) {
			EXPECT2(TOK_STRING, &val);
			post_set_ban_message(post, val.string);
		} else if (str_equal(token.string, "timestamp")) {
			EXPECT2(TOK_NUMBER, &val);
			post_set_timestamp(post, val.number);
		} else if (str_equal(token.string, "subject")) {
			EXPECT2(TOK_STRING, &val);
			post_set_subject(post, val.string);
		} else if (str_equal(token.string, "text")) {
			EXPECT2(TOK_STRING, &val);
			post_set_text(post, val.string);
		} else if (str_equal(token.string, "uploads")) {
			EXPECT(TOK_ARRAY_BEGIN);
			if (parse_array(parse_upload, post) == -1)
				return -1;
		} else {
			val = json_get_token();
			json_skip_structure(&val);
		}
		free_token(&val);

		free_token(&token);
	}
}

static int parse_thread(struct board *board)
{
	struct thread *thread = thread_new();
	struct thread *prev = board_last_thread(board);
	thread_set_board(thread, board);
	if (!board_first_thread(board))
		board_set_first_thread(board, thread);
	board_set_last_thread(board, thread);

	thread_set_prev_thread(thread, prev);
	if (prev)
		thread_set_next_thread(prev, thread);

	uint64 thread_count = board_thread_count(board);
	++thread_count;
	board_set_thread_count(board, thread_count);

	while (1) {
		struct json_token token = json_get_token();
		if (token.type  == TOK_OBJ_END)
			return 0;
		if (token.type != TOK_STRING) {
			free_token(&token);
			return -1;
		}

		EXPECT(TOK_COLON);

		struct json_token val = {0};
		if (str_equal(token.string, "closed")) {
			EXPECT2(TOK_NUMBER, &val);
			thread_set_closed(thread, val.number);
		} else if (str_equal(token.string, "pinned")) {
			EXPECT2(TOK_NUMBER, &val);
			thread_set_pinned(thread, val.number);
		} else if (str_equal(token.string, "saged")) {
			EXPECT2(TOK_NUMBER, &val);
			thread_set_saged(thread, val.number);
		} else if (str_equal(token.string, "posts")) {
			EXPECT(TOK_ARRAY_BEGIN);
			if (parse_array(parse_post, thread) == -1)
				return -1;
		} else {
			val = json_get_token();
			json_skip_structure(&val);
		}
		free_token(&val);

		free_token(&token);
	}
}

static int parse_board(void *unused)
{
	struct board *board = board_new();
	struct board *prev = master_last_board(master);
	if (!master_first_board(master))
		master_set_first_board(master, board);
	master_set_last_board(master, board);
	board_set_prev_board(board, prev);
	if (prev)
		board_set_next_board(prev, board);

	while (1) {
		struct json_token token = json_get_token();
		if (token.type == TOK_OBJ_END)
			return 0;
		if (token.type != TOK_STRING) {
			free_token(&token);
			return -1;
		}

		EXPECT(TOK_COLON);

		struct json_token val = {0};
		if (str_equal(token.string, "id")) {
			EXPECT2(TOK_NUMBER, &val);
			board_set_id(board, val.number);
			if (board_id(board) > master_board_counter(master))
				master_set_board_counter(master, board_id(board));
		} else if (str_equal(token.string, "name")) {
			EXPECT2(TOK_STRING, &val);
			board_set_name(board, val.string);
		} else if (str_equal(token.string, "title")) {
			EXPECT2(TOK_STRING, &val);
			board_set_title(board, val.string);
		} else if (str_equal(token.string, "threads")) {
			EXPECT(TOK_ARRAY_BEGIN);
			if (parse_array(parse_thread, board) == -1)
				return -1;
		} else {
			val = json_get_token();
			json_skip_structure(&val);
		}
		free_token(&val);

		free_token(&token);
	}
}

static int parse_bids(int64 **bids)
{
	EXPECT(TOK_ARRAY_BEGIN);
	array tmp = {0};
	size_t count = 0;
	struct json_token token = {0};
	while (1) {
		token = json_get_token();
		if (token.type == TOK_ARRAY_END)
			break;
		if (token.type != TOK_NUMBER)
			return -1;
		int64 *bid = array_allocate(&tmp, sizeof(int64), count++);
		*bid = token.number;
	}
	if (count > 0) {
		*bids = db_alloc0(sizeof(int64)*(count+1));
		memcpy(*bids, array_start(&tmp), sizeof(int64)*count);
		(*bids)[count] = -1;
		db_invalidate(db, *bids);
	} else {
		*bids = NULL;
	}
	array_reset(&tmp);
	free_token(&token);
	return 0;
}

static int parse_user(void *unused)
{
	struct user *user = user_new();
	struct user *prev = master_last_user(master);
	if (!master_first_user(master))
		master_set_first_user(master, user);
	master_set_last_user(master, user);
	user_set_prev_user(user, prev);
	if (prev)
		user_set_next_user(prev, user);

	while (1) {
		struct json_token token = json_get_token();
		if (token.type == TOK_OBJ_END)
			return 0;
		if (token.type != TOK_STRING) {
			free_token(&token);
			return -1;
		}

		EXPECT(TOK_COLON);

		struct json_token val = {0};
		if (str_equal(token.string, "id")) {
			EXPECT2(TOK_NUMBER, &val);
			user_set_id(user, val.number);
			if (user_id(user) > master_user_counter(master))
				master_set_user_counter(master, user_id(user));
		} else if (str_equal(token.string, "name")) {
			EXPECT2(TOK_STRING, &val);
			user_set_name(user, val.string);
		} else if (str_equal(token.string, "password")) {
			EXPECT2(TOK_STRING, &val);
			user_set_password(user, val.string);
		} else if (str_equal(token.string, "email")) {
			EXPECT2(TOK_STRING, &val);
			user_set_email(user, val.string);
		} else if (str_equal(token.string, "type")) {
			EXPECT2(TOK_NUMBER, &val);
			user_set_type(user, val.number);
		} else if (str_equal(token.string, "boards")) {
			int64 *bids = NULL;
			if (parse_bids(&bids) < 0)
				return -1;
			user_set_boards(user, bids);
		} else {
			val = json_get_token();
			json_skip_structure(&val);
		}
		free_token(&val);

		free_token(&token);
	}
}

static int parse_ban(void *unused)
{
	struct ban *ban = ban_new();

	while (1) {
		struct json_token token = json_get_token();
		if (token.type == TOK_OBJ_END) {
			insert_ban(ban);
			return 0;
		}
		if (token.type != TOK_STRING) {
			free_token(&token);
			return -1;
		}

		EXPECT(TOK_COLON);

		struct json_token val = {0};
		if (str_equal(token.string, "range")) {
			EXPECT2(TOK_STRING, &val);
			struct ip_range range = {0};
			scan_ip_range(val.string, &range);
			ban_set_range(ban, range);
		} else if (str_equal(token.string, "enabled")) {
			EXPECT2(TOK_NUMBER, &val);
			ban_set_enabled(ban, val.number);
		} else if (str_equal(token.string, "hidden")) {
			EXPECT2(TOK_NUMBER, &val);
			ban_set_hidden(ban, val.number);
		} else if (str_equal(token.string, "type")) {
			EXPECT2(TOK_NUMBER, &val);
			ban_set_type(ban, val.number);
		} else if (str_equal(token.string, "target")) {
			EXPECT2(TOK_NUMBER, &val);
			ban_set_target(ban, val.number);
		} else if (str_equal(token.string, "id")) {
			EXPECT2(TOK_NUMBER, &val);
			ban_set_id(ban, val.number);
			if (ban_id(ban) > master_ban_counter(master))
				master_set_ban_counter(master, ban_id(ban));
		} else if (str_equal(token.string, "timestamp")) {
			EXPECT2(TOK_NUMBER, &val);
			ban_set_timestamp(ban, val.number);
		} else if (str_equal(token.string, "duration")) {
			EXPECT2(TOK_NUMBER, &val);
			ban_set_duration(ban, val.number);
		} else if (str_equal(token.string, "post")) {
			EXPECT2(TOK_NUMBER, &val);
			ban_set_post(ban, val.number);
		} else if (str_equal(token.string, "reason")) {
			EXPECT2(TOK_STRING, &val);
			ban_set_reason(ban, val.string);
		} else if (str_equal(token.string, "mod")) {
			EXPECT2(TOK_NUMBER, &val);
			ban_set_mod(ban, val.number);
		} else if (str_equal(token.string, "mod_name")) {
			EXPECT2(TOK_STRING, &val);
			ban_set_mod_name(ban, val.string);
		} else if (str_equal(token.string, "boards")) {
			int64 *bids = NULL;
			if (parse_bids(&bids) < 0)
				return -1;
			ban_set_boards(ban, bids);
		} else {
			val = json_get_token();
			json_skip_structure(&val);
		}

		free_token(&val);

		free_token(&token);
	}
}

static int parse_report(void *unused)
{
	struct report *report = report_new();
	struct report *prev = master_last_report(master);
	if (!master_first_report(master))
		master_set_first_report(master, report);
	master_set_last_report(master, report);
	report_set_prev_report(report, prev);
	if (prev)
		report_set_next_report(prev, report);

	while (1) {
		struct json_token token = json_get_token();
		if (token.type == TOK_OBJ_END)
			return 0;
		if (token.type != TOK_STRING) {
			free_token(&token);
			return -1;
		}

		EXPECT(TOK_COLON);

		struct json_token val = {0};
		if (str_equal(token.string, "id")) {
			EXPECT2(TOK_NUMBER, &val);
			report_set_id(report, val.number);
			if (report_id(report) > master_report_counter(master))
				master_set_report_counter(master, report_id(report));
		} else if (str_equal(token.string, "post_id")) {
			EXPECT2(TOK_NUMBER, &val);
			report_set_post_id(report, val.number);
		} else if (str_equal(token.string, "thread_id")) {
			EXPECT2(TOK_NUMBER, &val);
			report_set_thread_id(report, val.number);
		} else if (str_equal(token.string, "board_id")) {
			EXPECT2(TOK_NUMBER, &val);
			report_set_board_id(report, val.number);
		} else if (str_equal(token.string, "type")) {
			EXPECT2(TOK_NUMBER, &val);
			report_set_type(report, val.number);
		} else if (str_equal(token.string, "reporter_ip")) {
			EXPECT2(TOK_STRING, &val);
			struct ip ip;
			scan_ip(val.string, &ip);
			report_set_reporter_ip(report, ip);
		} else if (str_equal(token.string, "reporter_uid")) {
			EXPECT2(TOK_NUMBER, &val);
			report_set_reporter_uid(report, val.number);
		} else if (str_equal(token.string, "timestamp")) {
			EXPECT2(TOK_NUMBER, &val);
			report_set_timestamp(report, val.number);
		} else if (str_equal(token.string, "comment")) {
			EXPECT2(TOK_STRING, &val);
			report_set_comment(report, val.string);
		} else {
			val = json_get_token();
			json_skip_structure(&val);
		}
		free_token(&val);

		free_token(&token);
	}

}


int import()
{
	EXPECT(TOK_OBJ_BEGIN);

	begin_transaction();

	while (1) {
		struct json_token token = json_get_token();
		if (token.type == TOK_OBJ_END)
			break;
		if (token.type != TOK_STRING) {
			free_token(&token);
			return -1;
		}

		EXPECT(TOK_COLON);

		struct json_token val = {0};
		if (str_equal(token.string, "boards")) {
			EXPECT(TOK_ARRAY_BEGIN);
			if (parse_array(parse_board, 0) == -1)
				return -1;
		} else if (str_equal(token.string, "users")) {
			EXPECT(TOK_ARRAY_BEGIN);
			if (parse_array(parse_user, 0) == -1)
				return -1;
		} else if (str_equal(token.string, "bans")) {
			EXPECT(TOK_ARRAY_BEGIN);
			if (parse_array(parse_ban, 0) == -1)
				return -1;
		} else if (str_equal(token.string, "reports")) {
			EXPECT(TOK_ARRAY_BEGIN);
			if (parse_array(parse_report, 0) == -1)
				return -1;
		} else {
			val = json_get_token();
			json_skip_structure(&val);
		}
		free_token(&val);

		free_token(&token);
	}
	printf("Success\n");
	commit();
}
