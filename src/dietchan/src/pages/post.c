#define _BSD_SOURCE 1
#define _GNU_SOURCE 1
#define _XOPEN_SOURCE 1
#include "post.h"

#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>

#include <libowfat/byte.h>
#include <libowfat/case.h>
#include <libowfat/str.h>
#include <libowfat/scan.h>
#include <libowfat/fmt.h>
#include <libowfat/open.h>
#include <libowfat/textcode.h>
#include <libowfat/ip4.h>
#include <libowfat/ip6.h>

#include "../util.h"
#include "../db.h"
#include "../upload_job.h"
#include "../captcha.h"
#include "../bans.h"
#include "../permissions.h"
#include "../tpl.h"
#include "../mime_types.h"


static int  post_page_header (http_context *http, char *key, char *val);
static int  post_page_post_param (http_context *http, char *key, char *val);
static int  post_page_cookie (http_context *http, char *key, char *val);
static int  post_page_file_begin (http_context *http, char *name, char *filename, char *content_type);
static int  post_page_file_content (http_context *http, char *buf, size_t length);
static int  post_page_file_end (http_context *http);
static int  post_page_finish (http_context *http);
static void post_page_finalize(http_context *http);

static char *post_page_upload_job_mime(struct upload_job *upload_job, char **mime_types);
static void post_page_upload_job_finish(struct upload_job *upload_job);
static void post_page_upload_job_error(struct upload_job *upload_job, int status, char *message);

void post_page_init(http_context *http)
{
	struct post_page *page = malloc0(sizeof(struct post_page));

	page->board = -1;
	page->thread = -1;
	page->pending = 0;

	http->info = page;

	http->header       = post_page_header;
	http->post_param   = post_page_post_param;
	http->cookie       = post_page_cookie;
	http->file_begin   = post_page_file_begin;
	http->file_content = post_page_file_content;
	http->file_end     = post_page_file_end;
	http->finish       = post_page_finish;
	http->finalize     = post_page_finalize;

	// Optional parameters
	page->username = strdup("");
	page->password = strdup("");
	page->subject = strdup("");
	page->role = strdup("");

	page->ip = http->ip;
}

static int post_page_header (http_context *http, char *key, char *val)
{
	struct post_page *page = (struct post_page*)http->info;

	PARAM_STR("User-Agent", page->user_agent);

	if (case_equals("X-Forwarded-For", key)) {
		parse_x_forwarded_for(&page->x_forwarded_for, val);
		return 0;
	}

	if (case_equals("X-Real-IP", key)) {
		scan_ip(val, &page->x_real_ip);
		return 0;
	}

	return 0;
}

static int post_page_post_param (http_context *http, char *key, char *val)
{
	struct post_page *page = (struct post_page*)http->info;

	PARAM_I64("thread",        page->thread);
	PARAM_I64("board",         page->board);
	PARAM_STR("subject",       page->subject);
	PARAM_STR("username2",     page->username);
	PARAM_STR("text2",         page->text);
	PARAM_STR("password",      page->password);
	PARAM_I64("sage",          page->sage);

	PARAM_STR("role",          page->role);
	PARAM_I64("pin",           page->mod_pin);
	PARAM_I64("close",         page->mod_close);

	PARAM_STR("captcha",       page->captcha);
	PARAM_X64("captcha_id",    page->captcha_id);
	PARAM_X64("captcha_token", page->captcha_token);

	// Bot trap
	if (case_equals(key, "username") ||
	    case_equals(key, "text") ||
	    case_equals(key, "comment") ||
	    case_equals(key, "website")) {
		if (val[0] != '\0')
			page->is_bot = 1;
		return 0;
	}

	if (case_equals(key, "dummy")) {
		return 0;
	}

	HTTP_FAIL(BAD_REQUEST);
}

static int post_page_cookie (http_context *http, char *key, char *val)
{
	struct post_page *page = (struct post_page*)http->info;
	PARAM_SESSION();
	return 0;
}

static int post_page_file_begin (http_context *http, char *name, char *filename, char *content_type)
{
	struct context* ctx = (context*)http;
	struct post_page *page = (struct post_page*)http->info;

	if (page->aborted)
		return ERROR;

	if (page->is_bot) // Don't waste any resources if it's a bot
		return 0;

	if (!case_equals(name, "file"))
		HTTP_FAIL(BAD_REQUEST);

	// We ignore the client-sent mime type since we cannot trust the information anyway.
	(void) content_type;

	size_t count = array_length(&page->upload_jobs, sizeof(struct upload_job));
	struct upload_job *upload_job = array_allocate(&page->upload_jobs, sizeof(struct upload_job), count);
	upload_job_init(upload_job, DOC_ROOT "/uploads/");
	upload_job->original_name = strdup(filename);
	upload_job->info = http;
	upload_job->mime = post_page_upload_job_mime;
	upload_job->finished = post_page_upload_job_finish;
	upload_job->error = post_page_upload_job_error;
	page->current_upload_job = upload_job;

	return 0;
}

static int post_page_file_content (http_context *http, char *buf, size_t length)
{
	struct post_page *page = (struct post_page*)http->info;
	context *ctx = (context*)http;

	if (page->aborted)
		return ERROR;

	if (page->is_bot) // Don't waste any resources if it's a bot
		return 0;

	if (array_length(&page->upload_jobs, sizeof(struct upload_job)) > MAX_FILES_PER_POST) {
		// This check must be in file_content instead of file_begin because in file_begin
		// we don't know whether the field is actually empty or not.

		PRINT_STATUS_HTML("413 Too many files");
		PRINT_SESSION();
		PRINT_BODY();
		PRINT(S("<h1>Error</h1>"
		        "<p>You may only attach up to "), I64(MAX_FILES_PER_POST), S(" files.</p>"));
		PRINT_EOF();

		upload_job_abort(page->current_upload_job);
		page->aborted = 1;
		return ERROR;
	}

	if (page->current_upload_job->size+length > MAX_UPLOAD_SIZE) {
		PRINT_STATUS_HTML("413 File too large");
		PRINT_SESSION();
		PRINT_BODY();
		PRINT(S("<h1>Error</h1>"
		        "<p>The file "), E(page->current_upload_job->original_name), S(
		        " is larger than the allowed maximum of "), HK(MAX_UPLOAD_SIZE), S("B."));

		PRINT_EOF();

		upload_job_abort(page->current_upload_job);
		page->aborted = 1;
		return ERROR;
	}

	upload_job_write_content(page->current_upload_job, buf, length);

	return 0;
}


static int post_page_file_end (http_context *http)
{
	struct post_page *page = (struct post_page*)http->info;
	context *ctx = (context*)http;

	if (page->is_bot) // Don't waste any resources if it's a bot
		return 0;

	if (page->current_upload_job->size == 0) {
		// Empty form field, ignore
		upload_job_finalize(page->current_upload_job);
		page->current_upload_job = 0;
		ssize_t upload_job_count = array_length(&page->upload_jobs, sizeof(struct upload_job));
		array_truncate(&page->upload_jobs, sizeof(struct upload_job), upload_job_count - 1);
	} else {
		upload_job_write_eof(page->current_upload_job);
		++page->pending;

		// Since uploads are handled asynchronously, we must increase the reference count of the
		// http_context. The reason is that the connection could already be closed by the client
		// when the asynchronous job completes. If we didn't increment the reference count, the closing
		// of the connection would cause the http_context to be destroyed, leading to a crash later.
		context_addref(ctx);
	}

	return 0;
}


static char* post_page_upload_job_mime(struct upload_job *upload_job, char **mime_types)
{
	// Validate mime type
	http_context *http = (http_context*)upload_job->info;
	struct post_page *page = (struct post_page*)http->info;

	const char *original_ext = strrchr(upload_job->original_name, '.');

	char **mime=0;

	// Check if any detected mime type is allowed
	for (mime=&mime_types[0]; *mime; ++mime) {
		if (is_mime_allowed(*mime) && is_valid_extension(*mime, original_ext))
			break;
	}

	// If no valid mime was found, print error message and abort
	if (!(*mime)) {
		if (!is_mime_allowed(mime_types[0])) {
			PRINT_STATUS_HTML("415 Unsupported media type");
			PRINT_SESSION();
			PRINT_BODY();
			PRINT(S("<h1>Error</h1>"
			        "<p>Unsupported mime type: "), E(mime_types[0]), S("<br>"),
			        E(upload_job->original_name), S("</p>"));

			PRINT_EOF();
		} else if (!is_valid_extension(mime_types[0], original_ext)) {
			PRINT_STATUS_HTML("415 Unsupported media type");
			PRINT_SESSION();
			PRINT_BODY();
			PRINT(S("<h1>Error</h1>"
			        "<p>Invalid file extension '"),original_ext?E(original_ext):S(""),
			      S("' for mime type '"), E(mime_types[0]), S("'<br>"),
			      E(upload_job->original_name), S("</p>"));

			PRINT_EOF();
		}

		upload_job_abort(upload_job);
		page->aborted = 1;
	}

	return *mime;
}

static void post_page_upload_job_finish(struct upload_job *upload_job)
{
	http_context *http = (http_context*)upload_job->info;
	context *ctx = (context*)http;
	struct post_page *page = (struct post_page*)http->info;

	--page->pending;
	post_page_finish(http);
	context_unref(ctx);
}

static void post_page_upload_job_error(struct upload_job *upload_job, int status, char *message)
{
	http_context *http = (http_context*)upload_job->info;
	context *ctx = (context*)http;
	struct post_page *page = (struct post_page*)http->info;

	// We could have more than one error, but we can only handle the first one.
	if (!page->aborted) {
		PRINT_STATUS_HTML("500 Internal Server Error");
		PRINT_SESSION();
		PRINT_BODY();
		PRINT(S("<h1>Error</h1>"
		        "<p>Could not process file: "), E(upload_job->original_name), S("<br>Corrupt file?</p>"));
		PRINT_EOF();
	}
	upload_job_abort(upload_job);
	page->aborted = 1;

	--page->pending;
	post_page_finish(http);
	context_unref(ctx);
}

static int post_page_finish (http_context *http)
{
	struct post_page *page = (struct post_page*)http->info;

	// We aborted due to an error and already sent a response
	if (page->aborted)
		return ERROR;

	// We are still waiting for uploads to be processed
	if (page->pending > 0)
		return 0;

	// Fake successful error code for bots in case they evaluate it
	if (page->is_bot) {
		PRINT_STATUS_HTML("200 OK");
		PRINT_SESSION();
		PRINT_BODY();
		PRINT(S("<h1>Hello Robot :)</h1>"));
		PRINT_EOF();
		return 0;
	}

	struct board  *board;
	struct thread *thread;
	struct post   *post;

	if (page->board == -1 && page->thread == -1)
		HTTP_FAIL(BAD_REQUEST);

	if (page->thread == -1) {
		board = find_board_by_id(page->board);
		if (!board) {
			PRINT_STATUS_HTML("404 Not Found");
			PRINT_SESSION();
			PRINT_BODY();
			PRINT(S("<h1>That board does not exist.</h1>"));
			PRINT_EOF();
			return ERROR;
		}
	} else {
		thread = find_thread_by_id(page->thread);
		if (!thread) {
			PRINT_STATUS_HTML("404 Not Found");
			PRINT_SESSION();
			PRINT_BODY();
			PRINT(S("<h1>That thread isn't anywhere to be seen.exist</h1>"));
			PRINT_EOF();
			return ERROR;
		}

		board = thread_board(thread);

		if (thread_closed(thread) &&
		    !(is_mod_for_board(page->user, board) && page->role[0] != '\0')) {
			PRINT_STATUS_HTML("402 Verboten");
			PRINT_SESSION();
			PRINT_BODY();
			PRINT(S("<h1>Faden geschlossen.</h1>"));
			PRINT_EOF();
			return ERROR;
		}
	}

	// Check if user is banned

	int64 banned = any_ip_affected(&page->ip, &page->x_real_ip, &page->x_forwarded_for,
	                               board, BAN_TARGET_POST, is_banned);

	if (banned) {
		PRINT_REDIRECT("302 Found",
		               S(PREFIX), S("/banned"));
		return ERROR;
	}

	if (page->thread == -1 && !can_make_thread(page->user, &page->ip, &page->x_real_ip,
	                                           &page->x_forwarded_for, board)) {
			PRINT_STATUS_HTML("402 Verboten");
			PRINT_SESSION();
			PRINT_BODY();
			PRINT(S("<h1>You cannot create a thread in this board.</h1>"));
			PRINT_EOF();
			return ERROR;
	}

	// New threads must contain text.
	// Posts without text are okay, as long as they contain at least one file.
	if ((!page->text || page->text[0] == '\0') &&
	    !(page->thread != -1 && array_length(&page->upload_jobs, sizeof(struct upload_job)) > 0)) {
		PRINT_STATUS_HTML("400 Not okay");
		PRINT_SESSION();
		PRINT_BODY();
		PRINT(S("<h1>You need to put text into your post.</h1>"));
		PRINT_EOF();
		return ERROR;
	}

	// New threads must contain an image
	if (page->thread == -1 && array_length(&page->upload_jobs, sizeof(struct upload_job)) <= 0) {
		PRINT_STATUS_HTML("400 Not okay");
		PRINT_SESSION();
		PRINT_BODY();
		PRINT(S("<h1>New threads must have an image attached.</h1>"));
		PRINT_EOF();
		return ERROR;
	}

	// Length checks
	if (strlen(page->text) > POST_MAX_BODY_LENGTH) {
		PRINT_STATUS_HTML("400 Not okay");
		PRINT_SESSION();
		PRINT_BODY();
		PRINT(S("<h1>That post is too long! (maximal "), I64(POST_MAX_BODY_LENGTH), S(" Zeichen)</h1>"));
		PRINT_EOF();
		return ERROR;
	}

	if (strlen(page->subject) > POST_MAX_SUBJECT_LENGTH) {
		PRINT_STATUS_HTML("400 Not okay");
		PRINT_SESSION();
		PRINT_BODY();
		PRINT(S("<h1>The subject is too long. It should be at most (maximal "), I64(POST_MAX_SUBJECT_LENGTH), S(" characters.)</h1>"));
		PRINT_EOF();
		return ERROR;
	}

	if (strlen(page->username) > POST_MAX_NAME_LENGTH) {
		PRINT_STATUS_HTML("400 Not okay");
		PRINT_SESSION();
		PRINT_BODY();
		PRINT(S("<h1>Name ist zu lang! (maximal "), I64(POST_MAX_NAME_LENGTH), S(" Zeichen)</h1>"));
		PRINT_EOF();
		return ERROR;
	}

	// Check if user is flood-limited

	int64 flood = any_ip_affected(&page->ip, &page->x_real_ip, &page->x_forwarded_for,
	                              board, BAN_TARGET_POST, is_flood_limited);

	if (flood) {
		uint64 now = time(0);
		PRINT_STATUS_HTML("403 Forbidden");
		PRINT_BODY();
		PRINT(S("<p>Flood protection: You can only read the next post in "), U64(flood - now), S(" seconds.</p>"));
		PRINT_EOF();
		return ERROR;
	}

	// Check captcha
	if (any_ip_affected(&page->ip, &page->x_real_ip, &page->x_forwarded_for,
	                    board, BAN_TARGET_POST, is_captcha_required)) {
		struct captcha *captcha = find_captcha_by_id(page->captcha_id);
		if (!captcha && master_captcha_count(master) <= 0) {
			PRINT_STATUS_HTML("500 Internal Error");
			PRINT_BODY();
			PRINT(S("<h1>500 Internal Error</h1>"
			        "<p>A captcha is required for this action, but there are no captchas enabled. "
			        "Unless they are activated, in which case check the logs.</p>"));
			PRINT_EOF();
			return ERROR;
		}
		if (!page->captcha || str_equal(page->captcha, "")) {
			PRINT_STATUS_HTML("403 Forbidden");
			PRINT_BODY();
			PRINT(S("<p>You didn't enter the captcha.</p>"));
			PRINT_EOF();
			return ERROR;
		}
		if (!captcha || captcha_token(captcha) != page->captcha_token) {
			PRINT_STATUS_HTML("403 Verboten");
			PRINT_BODY();
			PRINT(S("<p>The captcha expired.</p>"));
			PRINT_EOF();
			return ERROR;
		}
		int valid = case_equals(captcha_solution(captcha), page->captcha);
		if (valid)
			replace_captcha(captcha);
		else {
			invalidate_captcha(captcha);
			PRINT_STATUS_HTML("403 Forbidden");
			PRINT_BODY();
			PRINT(S("<p>The answer for the captcha is incorrect.</p>"));
			PRINT_EOF();
			return ERROR;
		}
	}

	// We now know we can create the post
	page->success = 1;

	begin_transaction();

	if (page->thread == -1) {
		// Create new thread
		thread = thread_new();
		thread_set_board(thread, board);

		bump_thread(thread);

		uint64 thread_count = board_thread_count(board);
		++thread_count;
		board_set_thread_count(board, thread_count);

		post = post_new();
		thread_set_first_post(thread, post);
		thread_set_last_post(thread, post);


		// Prune oldest thread
		if (thread_count > MAX_PAGES*THREADS_PER_PAGE)
			delete_thread(board_last_thread(board));
	} else {
		// Create reply
		post = post_new();
		struct post *prev = thread_last_post(thread);
		post_set_next_post(prev, post);
		post_set_prev_post(post, prev);
		thread_set_last_post(thread, post);

		// Bump thread unless post was saged or whole thread is saged.
		if (!page->sage && !thread_saged(thread))
			bump_thread(thread);
	}

	uint64 post_count = thread_post_count(thread);
	++post_count;
	thread_set_post_count(thread, post_count);

	// Autosage
	if (thread_post_count(thread) == BUMP_LIMIT-1)
		thread_set_saged(thread,1);

	// Autoclose
	if (thread_post_count(thread) == POST_LIMIT-1)
		thread_set_closed(thread,1);

	// Moderation
	if (is_mod_for_board(page->user, board)) {
		if (page->mod_pin)
			thread_set_pinned(thread, 1);
		if (page->mod_close)
			thread_set_closed(thread, 1);
	}

	post_set_id(post, master_post_counter(master)+1);
	master_set_post_counter(master, post_id(post));
	db_hashmap_insert(&post_tbl, &post_id(post), post);

	uint64 timestamp = time(NULL);

	const char *password = "";
	if (page->password[0] != '\0')
		password = crypt_password(page->password);

	// We don't support tripcodes at the moment, strip everything after # for security.
	page->username[str_chr(page->username, '#')] = '\0';

	post_set_thread(post, thread);
	post_set_timestamp(post, timestamp);
	post_set_subject(post, page->subject);
	post_set_username(post, page->username);
	post_set_text(post, page->text);
	post_set_password(post, password);
	post_set_ip(post, page->ip);
	post_set_x_real_ip(post, page->x_real_ip);
	if (array_bytes(&page->x_forwarded_for) > 0) {
		size_t len = array_length(&page->x_forwarded_for, sizeof(struct ip));
		struct ip *ips = db_alloc(db, sizeof(struct ip)*len);
		byte_copy(ips, sizeof(struct ip)*len, array_start(&page->x_forwarded_for));
		db_invalidate_region(db, ips, sizeof(struct ip)*len);
		post_set_x_forwarded_for_count(post, len);
		post_set_x_forwarded_for(post, ips);
	}

	post_set_sage(post, page->sage);

	if (is_mod_for_board(page->user, board)) {
		if (case_equals(page->role, "mod"))
			post_set_user_role(post, USER_MOD);
		else if (case_equals(page->role, "admin") && user_type(page->user) == USER_ADMIN)
			post_set_user_role(post, USER_ADMIN);
	}

	for (int i=0; i<array_length(&page->upload_jobs, sizeof(struct upload_job)); ++i) {
		struct upload_job *upload_job = array_get(&page->upload_jobs, sizeof(struct upload_job), i);
		if (!upload_job->ok)
			continue;
		if (upload_job->size == 0)
			continue;

		struct upload *up = upload_new();

		// Use timestamp to generate file name
		uint64 upload_id = timestamp*1000 + 1;
		uint64 last_upload_id = master_last_upload(master);
		if (upload_id <= last_upload_id)
			upload_id = last_upload_id+1;

		master_set_last_upload(master, upload_id);

		char filename[32];
		byte_zero(filename, sizeof(filename));
		fmt_uint64(filename, upload_id);
		strcat(filename, upload_job->file_ext);

		char thumb_filename[32];
		byte_zero(thumb_filename, sizeof(filename));
		fmt_uint64(thumb_filename, upload_id);
		strcat(thumb_filename, "s");
		strcat(thumb_filename, upload_job->thumb_ext);

		char file_path[256];
		strcpy(file_path, DOC_ROOT "/uploads/");
		strcat(file_path, filename);

		char thumb_path[256];
		strcpy(thumb_path, DOC_ROOT "/uploads/");
		strcat(thumb_path, thumb_filename);

		// Move temporary files to their final locations
		// Todo: handle errors
		if (rename(upload_job->file_path, file_path) < 0)
			printf("Renaming %s to %s failed: %s", upload_job->file_path, file_path, strerror(errno));
		if (rename(upload_job->thumb_path, thumb_path) < 0)
			printf("Renaming %s to %s failed: %s", upload_job->thumb_path, thumb_path, strerror(errno));

		upload_set_file(up, filename);
		upload_set_thumbnail(up, thumb_filename);
		upload_set_original_name(up, upload_job->original_name);
		upload_set_mime_type(up, upload_job->mime_type);
		upload_set_size(up, upload_job->size);
		upload_set_width(up, upload_job->width);
		upload_set_height(up, upload_job->height);
		upload_set_duration(up, upload_job->duration);
		upload_set_state(up, UPLOAD_NORMAL);

		if (i==0) {
			post_set_first_upload(post, up);
			post_set_last_upload(post, up);
		} else {
			struct upload *prev = post_last_upload(post);
			upload_set_prev_upload(up, prev);
			upload_set_next_upload(prev, up);
			post_set_last_upload(post, up);
		}
	}

	purge_expired_bans();

	if (is_external_ip(&page->ip) || !FLOOD_IGNORE_LOCAL_IP)
		create_global_ban(&page->ip, BAN_FLOOD, BAN_TARGET_POST, timestamp, FLOOD_LIMIT, post_id(post));
	for (size_t i=0; i<array_length(&page->x_forwarded_for, sizeof(struct ip)); ++i) {
		struct ip *ip = array_get(&page->x_forwarded_for, sizeof(struct ip), i);
		if (is_external_ip(&page->ip) || !FLOOD_IGNORE_LOCAL_IP)
			create_global_ban(ip, BAN_FLOOD, BAN_TARGET_POST, timestamp, FLOOD_LIMIT, post_id(post));
	}
	if (is_external_ip(&page->x_real_ip) || !FLOOD_IGNORE_LOCAL_IP)
		create_global_ban(&page->x_real_ip, BAN_FLOOD, BAN_TARGET_POST, timestamp, FLOOD_LIMIT, post_id(post));

	commit();

	PRINT_STATUS("302 Success");
	PRINT(S("Location: "));
	print_post_url(http, post, 1);
	PRINT(S("\r\n"));
	PRINT_SESSION();
	PRINT_BODY();
	PRINT_EOF();

	return 0;
}

static void post_page_finalize (http_context *http)
{
	struct post_page *page = (struct post_page*)http->info;

	free(page->subject);
	free(page->username);
	free(page->text);
	free(page->password);
	free(page->user_agent);
	free(page->role);
	array_reset(&page->x_forwarded_for);

	ssize_t upload_job_count = array_length(&page->upload_jobs, sizeof(struct upload_job));
	for (ssize_t i=0; i<upload_job_count; ++i) {
		struct upload_job *upload_job = array_get(&page->upload_jobs, sizeof(struct upload_job), i);
		if (!page->success)
			upload_job_abort(upload_job);
		upload_job_finalize(upload_job);
	}
	array_reset(&page->upload_jobs);

	free(page);
}

