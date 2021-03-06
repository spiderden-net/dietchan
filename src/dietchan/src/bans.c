#include "bans.h"

#include <time.h>

int ban_matches_ip(struct ban *ban, struct ip *ip)
{
	return ip_in_range(&ban_range(ban), ip);
}

int ban_matches_board(struct ban *ban, uint64 board_id)
{
	int64 *boards = ban_boards(ban);

	// Global ban
	if (!boards)
		return 1;

	for (int i=0; boards[i] >= 0; ++i) {
		if (boards[i] == (int64)board_id)
			return 1;
	}
	return 0;
}


void find_bans(struct ip *ip, find_bans_callback callback, void *extra)
{
	struct ip_range range = {0};
	range.ip = *ip;

	switch (ip->version) {
		case IP_V4: range.range =  32; break;
		case IP_V6: range.range = 128; break;
	}

	while (range.range >= 0) {
		for (struct ban *ban = db_hashmap_get(&ban_tbl, &range); ban; ban=ban_next_in_bucket(ban)) {
			if (ban_enabled(ban)) {
				callback(ban, ip, extra);
			}
		}
		--(range.range);
	}
}

struct is_banned_info {
	enum ban_target target;
	enum ban_type type;
	int64 expires;
	struct board *board;
};

static void is_banned_callback(struct ban *ban, struct ip *ip, void *extra)
{
	uint64 now = time(NULL);
	struct is_banned_info *info = (struct is_banned_info*)extra;
	if (ban_type(ban) == info->type &&
	    ban_target(ban) == info->target &&
	    ((ban_duration(ban) < 0) || (now <= ban_timestamp(ban) + ban_duration(ban))) &&
	    (!info->board || ban_matches_board(ban, board_id(info->board)))) {
		if (ban_duration(ban) > 0) {
			int64 expires = ban_timestamp(ban) + ban_duration(ban);
			if (expires > info->expires)
				info->expires = expires;
		} else {
			info->expires = -1;
		}
	}
}

int64 is_banned(struct ip *ip, struct board *board, enum ban_target target)
{
	struct is_banned_info info = {0};
	info.type = BAN_BLACKLIST;
	info.target = target;
	info.board = board;
	find_bans(ip, is_banned_callback, &info);
	return info.expires;
}

int64 is_flood_limited(struct ip *ip, struct board *board, enum ban_target target)
{
	struct is_banned_info info = {0};
	info.type = BAN_FLOOD;
	info.target = target;
	info.board = board;
	find_bans(ip, is_banned_callback, &info);
	return info.expires;
}

int64 is_captcha_required(struct ip *ip, struct board *board, enum ban_target target)
{
	struct is_banned_info info = {0};
	info.type = BAN_CAPTCHA_PERMANENT;
	info.target = target;
	info.board = board;
	find_bans(ip, is_banned_callback, &info);
	if (!info.expires) {
		info.type = BAN_CAPTCHA_ONCE;
		info.target = target;
		info.board = board;
		find_bans(ip, is_banned_callback, &info);
	}
	return info.expires;
}

int64 any_ip_affected(struct ip *ip, struct ip *x_real_ip, array *x_forwarded_for,
                      struct board *board, enum ban_target target,
                      int64 (*predicate)(struct ip *ip, struct board *board, enum ban_target target))
{
	int64 affected = 0;
	affected = predicate(ip, board, target);
	if (!affected)
		affected = predicate(x_real_ip, board, target);
	if (!affected) {
		size_t count = array_length(x_forwarded_for, sizeof(struct ip));
		for (size_t i=0; i<count; ++i) {
			struct ip *x = array_get(x_forwarded_for, sizeof(struct ip), i);
			if (affected = predicate(x, board, target))
				break;
		}
	}
	return affected;
}

void create_global_ban(const struct ip *ip, enum ban_type type, enum ban_target target,
                       uint64 timestamp, int64 duration, uint64 post)
{
	struct ban *ban = ban_new();
	uint64 ban_counter = master_ban_counter(master)+1;
	master_set_ban_counter(master, ban_counter);
	ban_set_id(ban, ban_counter);
	ban_set_enabled(ban, 1);
	ban_set_type(ban, BAN_FLOOD);
	ban_set_target(ban, BAN_TARGET_POST);
	ban_set_timestamp(ban, timestamp);
	ban_set_duration(ban, duration);
	struct ip_range range;
	range.ip = *ip;
	if (ip->version == IP_V6)
		range.range = 48;
	else
		range.range = 32;
	ban_set_range(ban, range);
	ban_set_post(ban, post);

	insert_ban(ban);
}

void purge_expired_bans()
{
	uint64 now = time(NULL);
	struct ban *ban = master_first_ban(master);
	while (ban) {
		struct ban *next = ban_next_ban(ban);
		if (ban_duration(ban) >= 0 && now > ban_timestamp(ban) + ban_duration(ban)) {
			delete_ban(ban);
		}
		ban = next;
	}
}
