#ifndef CONFIG_H
#define CONFIG_H

// -- Convenience --
#define KILO (1024UL)
#define MEGA (1024UL*1024UL)
#define GIGA (1024UL*1024UL*1024UL)

// -- Server stuff --
// The virtual "directory" in which the imageboard resides.
// E.g. if it should appear in http://example.com/foo/bar/, then the prefix is /foo/bar
#define PREFIX                           ""
// The path where uploads and static content are stored. Not visible to the public (although the content is).
#define DOC_ROOT                    "./www"

// -- Flood limits --

// Number of seconds to wait between creating two posts (seconds)
#define FLOOD_LIMIT                      10
// Number of seconds to wait between creating two reports (seconds)
#define REPORT_FLOOD_LIMIT               10
// Ignore local IP addresses like 127.0.0.1 for flood limits. Useful when using a reverse-proxy.
#define FLOOD_IGNORE_LOCAL_IP             1

// -- Bans --

#define DEFAULT_BAN_MESSAGE "THIS USER WAS BANNED FOR THIS POST"

// -- Boards --

// Number of preview posts for thread in board view
#define PREVIEW_REPLIES                   4
// Number of threads per page in board view
#define THREADS_PER_PAGE                 10
// Maximum number of pages per board
#define MAX_PAGES                        16

// -- Threads --

// Thread will go on autosage after this many posts
#define BUMP_LIMIT                      300
// Absolute limit of how many posts a thread can have. When reaching this limit, it is automatically
// closed.
#define POST_LIMIT                     500

// -- Posts --
#define POST_MAX_BODY_LENGTH          10000
#define POST_MAX_SUBJECT_LENGTH         100
#define POST_MAX_NAME_LENGTH            100
#define DEFAULT_NAME                "Anonymous"

// -- Uploads --
// Maximum filename length of an uploaded file
#define MAX_FILENAME_LENGTH             512
// Maximum length of a mime type
#define MAX_MIME_LENGTH                  64
// Maximum number of files attached to a post
#define MAX_FILES_PER_POST                4
// Maximum file size of a single upload
#define MAX_UPLOAD_SIZE           (10*MEGA)

// -- Thumbnails --
// Maximum resolution of generated thumbnails
#define THUMB_MAX_PHYSICAL_WIDTH        600
#define THUMB_MAX_PHYSICAL_HEIGHT       600
// Maximum dimensions of thumbnails as displayed in the HTML. It is a good idea to have a greater
// physical resolution and scale the image down in the browser because of HiDPI monitors.
#define THUMB_MAX_DISPLAY_WIDTH         350
#define THUMB_MAX_DISPLAY_HEIGHT        350
// Backend to use for thumbnail generation:
// - ImageMagick 6/7
#define MAGICK_COMMAND                   ""
// - ImageMagick 7+
//#define MAGICK_COMMAND           "magick"
// - GraphicsMagick
//#define MAGICK_COMMAND               "gm"

// -- Reports --
#define REPORT_MAX_COMMENT_LENGTH       100

// -- Captcha --
// Whether the captcha feature is enabled. 0=disabled, 1=enabled.
// Note that to actually use the captcha, you have to create a ban in the control panel and set the type to "captcha".
#define ENABLE_CAPTCHA                    1
// Captchas are pregenerated and randomly picked from this pool. Only correctly solved captchas are
// removed from the pool. This is so an attacker can't easily ddos the server by forcing it to constantly 
// generate new captchas.
// However, using a fixed captcha pool also has disadvantages: If it is too small, an attacker can simply
// wait for the same captcha to appear again and effectively brute-force the solution. If you see ever this
// happening, you should probably increase the pool size by an order of magnitude or more. 
// As an additional countermeasure, we could also add a timeout value to generated captchas or throttle 
// repeated captcha requests from the same IP, but this is not currently implemented.
#define CAPTCHA_POOL_SIZE              600
// Max number of parallel processes used for generating new captchas.
#define CAPTCHA_WORKERS                   4

// -- Technical definitions -- CAREFUL! --

// When changing these definitions, please note that some strings are allocated on the stack, so
// these constants should not be too big.
// Also, the purpose of these constants is to prevent errors or attacks. As such, they are just
// rough guidelines. The code may not always follow to these constants to the byte, but will stay
// within the right order of magnitude.
#define MAX_HEADER_LENGTH              2048
#define MAX_URL_LENGTH                 2048
#define MAX_REQUEST_LINE_LENGTH        2048
#define MAX_GET_PARAM_LENGTH           2048
#define MAX_POST_PARAM_LENGTH         16384
#define MAX_MULTIPART_BOUNDARY_LENGTH   128

#endif // CONFIG_H
