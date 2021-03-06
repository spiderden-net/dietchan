#include "upload_job.h"

#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <libowfat/byte.h>
#include <libowfat/buffer.h>
#include <libowfat/str.h>
#include <libowfat/fmt.h>
#include <libowfat/case.h>
#include <libowfat/open.h>
#include <libowfat/scan.h>

#include "config.h"
#include "util.h"
#include "mime_types.h"

static void start_mime_check_job(struct upload_job *upload_job);
static void finished_mime_check_job(struct upload_job *upload_job);
static void start_extract_meta_job(struct upload_job *upload_job);
static void finished_extract_meta_job(struct upload_job *upload_job);
static void start_thumbnail_job(struct upload_job *upload_job);
static void finished_thumbnail_job(struct upload_job *upload_job);

static int  upload_job_job_read(job_context *job, char *buf, size_t length);
static void upload_job_job_finish(job_context *job, int status);
static void upload_job_error(struct upload_job *upload_job, int status, char *message);

static void extract_meta_command(const char *file, const char *mime_type, char *command);
static void thumbnail_command(const char *file, int64 original_width, int64 original_height,
                              double original_duration, const char *mime_type,
                              const char *thumbnail_base, const char **ext, char *command);

void upload_job_init(struct upload_job *upload_job, char *upload_dir)
{
	byte_zero(upload_job, sizeof(struct upload_job));

	upload_job->ok = 1;

	upload_job->width = -1;
	upload_job->height = -1;
	upload_job->duration = -1;
	upload_job->upload_dir = strdup(upload_dir);
	upload_job->file_ext = "";
	upload_job->thumb_ext = "";

	upload_job->file_path = malloc(strlen(upload_dir) + 15);
	byte_zero(upload_job->file_path, strlen(upload_dir) + 15);
	strcpy(upload_job->file_path, upload_dir);
	strcat(upload_job->file_path, ".tmp");
	generate_random_string(&upload_job->file_path[strlen(upload_job->file_path)], 10, "0123456789");

	// For performance reasons, we only create the fd when we actually write something.
	upload_job->fd = -1;
}

void upload_job_finalize(struct upload_job *upload_job)
{
	if (!upload_job->ok) {
		// Aborted or error occured, clean up
		if (upload_job->file_path)
			unlink(upload_job->file_path);
		if (upload_job->thumb_path)
			unlink(upload_job->thumb_path);
	}
	free(upload_job->upload_dir);
	free(upload_job->file_path);
	free(upload_job->thumb_path);
	free(upload_job->mime_type);
	if (upload_job->fd >= 0)
		close(upload_job->fd);
	array_reset(&upload_job->job_output);
}

void upload_job_write_content(struct upload_job *upload_job, char *buf, size_t length)
{
	if (upload_job->fd < 0) {
		upload_job->fd = open_trunc(upload_job->file_path);
		io_closeonexec(upload_job->fd);
	}
	write(upload_job->fd, buf, length);
	upload_job->size += length;
}

void upload_job_write_eof(struct upload_job *upload_job)
{
	assert(upload_job->state == UPLOAD_JOB_UPLOADING);
	upload_job->state = UPLOAD_JOB_UPLOADED;

	if (upload_job->fd < 0) {
		upload_job->fd = open_trunc(upload_job->file_path);
		io_closeonexec(upload_job->fd);
	}

	close(upload_job->fd);
	start_mime_check_job(upload_job);
}

void upload_job_abort(struct upload_job *upload_job)
{
	upload_job->ok = 0;
	// Kill current job?
}

void upload_job_check_mime(struct upload_job *upload_job)
{
	start_mime_check_job(upload_job);
}

// --- Internal ---

static int upload_job_job_read(job_context *job, char *buf, size_t length)
{
	struct upload_job *upload_job = (struct upload_job*)job->info;
	array_catb(&upload_job->job_output, buf, length);
	return 0;
}

static void upload_job_job_finish(job_context *job, int status)
{
	struct upload_job *upload_job = (struct upload_job*)job->info;

	if (status != 0) {
		upload_job->ok = 0;
		upload_job_error(upload_job, 500, "Internal Server Error");
		return;
	}

	array_cat0(&upload_job->job_output);

	switch (upload_job->state) {
	case UPLOAD_JOB_MIMECHECKING:
		finished_mime_check_job(upload_job);
		break;
	case UPLOAD_JOB_EXTRACTING_META:
		finished_extract_meta_job(upload_job);
		break;
	case UPLOAD_JOB_THUMBNAILING:
		finished_thumbnail_job(upload_job);
		break;
	}
}

static void upload_job_error(struct upload_job *upload_job, int status, char *message)
{
	if (upload_job->error)
		upload_job->error(upload_job, status, message);
}

// --- MIME Checking ---

static void start_mime_check_job(struct upload_job *upload_job)
{
	assert(upload_job->state == UPLOAD_JOB_UPLOADED);

	char command[512];
	size_t i = 0;
	i += fmt_str(&command[i], "file --mime-type --brief -k -r ");
	i += fmt_str(&command[i], upload_job->file_path);

	// Older versions of file don't support the -k and -r flags.
	// Fallback in case the first command failed.
	i += fmt_str(&command[i], " || file --mime-type --brief ");
	i += fmt_str(&command[i], upload_job->file_path);
	command[i] = '\0';

	job_context *job = job_new(command);
	job->info = upload_job;
	job->read = upload_job_job_read;
	job->finish = upload_job_job_finish;

	upload_job->current_job = job;
	array_trunc(&upload_job->job_output);
	upload_job->state = UPLOAD_JOB_MIMECHECKING;
}

static void remove_trailing_space(char *s)
{
	ssize_t length = strlen(s);
	for (ssize_t i = length-1; isspace(s[i]) && i>=0; --i)
		s[i] = '\0';
}

static void finished_mime_check_job(struct upload_job *upload_job)
{
	assert(upload_job->state == UPLOAD_JOB_MIMECHECKING);

	// Parse mime types. Output may contain multiple types like this:
	// video/webm
	// - application/octet-stream
	char *s = array_start(&upload_job->job_output);
	char **mime_types = alloca(strlen(s)*sizeof(char*));
	char **t = &mime_types[0];
	int end=0;
	while (!end) {
		char *nl = &s[str_chr(s, '\n')];
		end = *nl == '\0';
		*nl = '\0';
		while (isspace(*s)) ++s;
		if (*s=='-') ++ s;
		while (isspace(*s)) ++s;
		remove_trailing_space(s);

		if (s[0] != '\0')
			*(t++) = s;

		s = nl + 1;
	}

	*t = 0;

	if (upload_job->mime) {
		const char *mime = upload_job->mime(upload_job, mime_types);
		if (mime) {
			upload_job->mime_type = strdup(mime);
			upload_job->file_ext = get_extension_for_mime_type(mime);
		} else {
			upload_job->ok = 0;
		}
	}

	upload_job->state = UPLOAD_JOB_MIMECHECKED;

	if (upload_job->ok)
		start_extract_meta_job(upload_job);
}

// --- Meta extraction ---

static void start_extract_meta_job(struct upload_job *upload_job)
{
	assert(upload_job->state == UPLOAD_JOB_MIMECHECKED);

	char buf[4096];
	extract_meta_command(upload_job->file_path, upload_job->mime_type, buf);

	job_context *job = job_new(buf);
	job->info = upload_job;
	job->read = upload_job_job_read;
	job->finish = upload_job_job_finish;

	upload_job->current_job = job;
	array_trunc(&upload_job->job_output);

	upload_job->state = UPLOAD_JOB_EXTRACTING_META;
}

static void finished_extract_meta_job(struct upload_job *upload_job)
{
	assert(upload_job->state == UPLOAD_JOB_EXTRACTING_META);

	buffer buf;
	buffer_fromarray(&buf, &upload_job->job_output);

	char   line[512];
	ssize_t line_length;
	int    int_val;
	double dbl_val;

	while ((line_length = buffer_getline(&buf, line, sizeof(line)-1)) > 0) {
		line[line_length] = '\0';
		if (case_starts(line, "width=")) {
			if (scan_int(&line[strlen("width=")], &int_val) > 0)
				upload_job->width = int_val;
		} else if (case_starts(line, "height=")) {
			if (scan_int(&line[strlen("height=")], &int_val) > 0)
				upload_job->height = int_val;
		} else if (case_starts(line, "duration=")) {
			if (scan_double(&line[strlen("duration=")], &dbl_val) > 0)
				upload_job->duration = dbl_val*1000L;
		} else if (case_starts(line, "Page")) {
			// Parse output of pdfinfo
			// The line looks like this:
			// "Page    1 size: 612 x 792 pts (letter)"
			size_t i = 0;
			size_t delta;
			double w,h;
			i += strlen("Page");
			i += scan_whiteskip(&line[i]);

			if (line[i++] != '1')
				continue;

			i += scan_whiteskip(&line[i]);

			if (!case_starts(&line[i], "size:"))
				continue;
			i += strlen("size:");

			i += scan_whiteskip(&line[i]);

			// Width
			i += (delta = scan_double(&line[i], &w));
			if (delta <= 0)
				continue;

			i += scan_whiteskip(&line[i]);

			if (line[i++] != 'x')
				continue;

			i += scan_whiteskip(&line[i]);
			
			// Height
			i += (delta = scan_double(&line[i], &h));
			if (delta <= 0)
				continue;

			upload_job->width = w;
			upload_job->height = h;
		}
	}

	upload_job->state = UPLOAD_JOB_EXTRACTED_META;

	if (upload_job->meta)
		upload_job->meta(upload_job, upload_job->width, upload_job->height, upload_job->duration);

	if (upload_job->ok)
		start_thumbnail_job(upload_job);
}

// --- Thumbnailing ---

static void start_thumbnail_job(struct upload_job *upload_job)
{
	assert(upload_job->state == UPLOAD_JOB_EXTRACTED_META);

	char *thumbnail_base = alloca(strlen(upload_job->file_path) + 2);
	strcpy(thumbnail_base, upload_job->file_path);
	strcat(thumbnail_base, "s");

	char buf[4096];
	const char *ext;

	thumbnail_command(upload_job->file_path, upload_job->width, upload_job->height, upload_job->duration,
	                  upload_job->mime_type, thumbnail_base, &ext, buf);

	upload_job->thumb_path = malloc(strlen(thumbnail_base) + strlen(ext));
	strcpy(upload_job->thumb_path, thumbnail_base);
	strcat(upload_job->thumb_path, ext);

	upload_job->thumb_ext = ext;

	job_context *job = job_new(buf);
	job->info = upload_job;
	job->read = upload_job_job_read;
	job->finish = upload_job_job_finish;

	upload_job->current_job = job;
	array_trunc(&upload_job->job_output);

	upload_job->state = UPLOAD_JOB_THUMBNAILING;
}

static void finished_thumbnail_job(struct upload_job *upload_job)
{
	assert(upload_job->state == UPLOAD_JOB_THUMBNAILING);

	upload_job->state = UPLOAD_JOB_THUMBNAILED;
	if (upload_job->finished)
		upload_job->finished(upload_job);
}

// --- Commands ---

static void extract_meta_command(const char *file, const char *mime_type, char *command)
{
	size_t i=0;
	if (case_starts(mime_type, "video/")) {
		i += fmt_str(&command[i], "ffprobe -v error -show_entries format=duration:stream=index,codec_types,width,height -of default=noprint_wrappers=1 ");
		i += fmt_str(&command[i], file);
	} else if (case_equals(mime_type, "application/pdf")) {
		i += fmt_str(&command[i], "pdfinfo -f 1 -l 1 ");
		i += fmt_str(&command[i], file);
	} else {
		int multipage=0;
		if (case_equals(mime_type, "image/gif"))
			multipage=1;
		i += fmt_str(&command[i], MAGICK_COMMAND " identify -format 'width=%w\\nheight=%h\\n' ");
		i += fmt_str(&command[i], file);
		if (multipage)
			i += fmt_str(&command[i], "[0]");
	}
	command[i] = '\0';
}

static void thumbnail_command(const char *file, int64 original_width, int64 original_height,
                              double original_duration, const char *mime_type, const char *thumbnail_base,
                              const char **ext, char *command)
{
	*ext = "";

	char thumb_file[512];
	strcpy(thumb_file, thumbnail_base);

	int multipage=0;

	size_t i=0;

	if (case_starts(mime_type, "video/")) {
		// Determine timestamp to use for thumbnail.
		// 1.8 seconds seems to work alright for most videos.
		// For very short clips we have to use a smaller value.
		if (original_duration >= 5000)
			i += fmt_str(&command[i], "ffmpeg -ss 00:00:01.800 -i ");
		else if (original_duration >= 1000)
			i += fmt_str(&command[i], "ffmpeg -ss 00:00:00.500 -i ");
		else if (original_duration >= 100)
			i += fmt_str(&command[i], "ffmpeg -ss 00:00:00.050 -i ");
		else
			i += fmt_str(&command[i], "ffmpeg -i ");
		i += fmt_str(&command[i], file);
		i += fmt_str(&command[i], " -vframes 1 -map 0:v -vf 'thumbnail=5,scale=iw*sar:ih' -f image2pipe -vcodec bmp - ");
		i += fmt_str(&command[i], " | ");
		// Call recursively to generate jpg thumbnail from bmp
		thumbnail_command("-", original_width, original_height, original_duration, "image/jpeg", thumbnail_base, ext, &command[i]);
		// Subcommand already added \0 at the end. Exit early so we don't truncate the command.
		return;
	} else if (case_equals(mime_type, "application/pdf")) {
		// pdftoppm is part of poppler-utils
		i += fmt_str(&command[i], "pdftocairo -singlefile -png -scale-to ");
		i += fmt_ulong(&command[i], THUMB_MAX_PHYSICAL_WIDTH);
		i += fmt_str(&command[i], " ");
		i += fmt_str(&command[i], file);
		i += fmt_str(&command[i], " - | ");
		// Call recursively to generate final png thumbnail
		thumbnail_command("-", original_width, original_height, original_duration, "image/png", thumbnail_base, ext, &command[i]);
		// Subcommand already added \0 at the end. Exit early so we don't truncate the command.
		return;
	} else if (case_equals(mime_type, "image/png") ||
	           case_equals(mime_type, "image/gif") ) {
		*ext = ".png";
		strcat(thumb_file, *ext);

		if (case_equals(mime_type, "image/gif") ||
		    case_equals(mime_type, "application/pdf"))
			multipage=1;

		i += fmt_str(&command[i], MAGICK_COMMAND " convert ");
		i += fmt_str(&command[i], file);
		if (multipage)
			i += fmt_str(&command[i], "[0]");

		i += fmt_str(&command[i], " -resize ");
		i += fmt_ulong(&command[i], THUMB_MAX_PHYSICAL_WIDTH);
		i += fmt_str(&command[i], "X");
		i += fmt_ulong(&command[i], THUMB_MAX_PHYSICAL_HEIGHT);
		i += fmt_str(&command[i], "\\> -quality 0 -profile data/sRGB.icc -strip ");
		i += fmt_str(&command[i], thumb_file);

		// Imagemagick's PNG8 capabilities suck, so use pngquant to further optimize the size (optional)
		i += fmt_str(&command[i], " && (pngquant -f 32 ");
		i += fmt_str(&command[i], thumb_file);
		i += fmt_str(&command[i], " -o ");
		i += fmt_str(&command[i], thumb_file);

		i += fmt_str(&command[i], " || true)");
	} else {
		*ext = ".jpg";
		strcat(thumb_file, *ext);

		i += fmt_str(&command[i], MAGICK_COMMAND " convert ");

		i += fmt_str(&command[i], "-define jpeg:size=");
		i += fmt_ulong(&command[i], 2*THUMB_MAX_PHYSICAL_WIDTH);
		i += fmt_str(&command[i], "X");
		i += fmt_ulong(&command[i], 2*THUMB_MAX_PHYSICAL_HEIGHT);

		i += fmt_str(&command[i], " -define jpeg:extent=20kb ");
		i += fmt_str(&command[i], file);

		i += fmt_str(&command[i], " -resize ");
		i += fmt_ulong(&command[i], THUMB_MAX_PHYSICAL_WIDTH);
		i += fmt_str(&command[i], "X");
		i += fmt_ulong(&command[i], THUMB_MAX_PHYSICAL_HEIGHT);
		i += fmt_str(&command[i], "\\>");

		i += fmt_str(&command[i], " -auto-orient -sharpen 0.1");
		// Hack: '-define jpeg:extent' doesn't work on GM, so we use a lower quality setting so our 
		// thumbnails don't end up too big.
		if (strcmp(MAGICK_COMMAND, "gm") == 0)
			i += fmt_str(&command[i], " -quality 20");
		else
			i += fmt_str(&command[i], " -quality 50");
		i += fmt_str(&command[i], " -sampling-factor 2x2,1x1,1x1");
		i += fmt_str(&command[i], " -profile data/sRGB.icc -strip ");
		i += fmt_str(&command[i], thumb_file);
	}
	command[i] = '\0';
}
