#define CB_API_IMPL
#include <Carbide/Recipe.h>

#if defined(_WIN32)
	#define WIN32_LEAN_AND_MEAN
	#include <io.h>
	#include <shlwapi.h>
	#include <wchar.h>
	#include <windows.h>
	#pragma comment(lib, "Shlwapi.lib")
#else
	#include <dirent.h>
	#include <dlfcn.h>
	#include <errno.h>
	#include <fcntl.h>
	#include <glob.h>
	#include <signal.h>
	#include <sys/ioctl.h>
	#include <sys/stat.h>
	#include <sys/types.h>
	#include <sys/wait.h>
	#include <unistd.h>
#endif

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef PATH_MAX
	#define PATH_MAX 4096
#endif

#if defined(_WIN32)
	#define CB_PATH_SEP '\\'
	#define CB_OTHER_SEP '/'
#else
	#define CB_PATH_SEP '/'
	#define CB_OTHER_SEP '\\'
#endif

static cb_context *g_ctx_singleton = CB_NULL;
static cb_cmd_handler_fn g_default_fn = CB_NULL;
static char *g_default_help = CB_NULL;

#define SGR_RESET "\x1b[0m"
#define SGR_BOLD "\x1b[1m"
#define FG_RED "\x1b[31m"
#define FG_YELLOW "\x1b[33m"
#define FG_CYAN "\x1b[36m"
#define FG_MAGENTA "\x1b[35m"
#define FG_DIM "\x1b[2m"

static inline int term_color_enabled_stderr(void) { return g_ctx_singleton && g_ctx_singleton->term.use_color_stderr; }
static inline int term_color_enabled_stdout(void) { return g_ctx_singleton && g_ctx_singleton->term.use_color_stdout; }

static void die(const char *msg) {
	if (term_color_enabled_stderr())
		fprintf(stderr, "%s%s%s %s%s%s\n", FG_RED, "carbide:", SGR_RESET, SGR_BOLD, msg, SGR_RESET);
	else
		fprintf(stderr, "carbide: %s\n", msg);
	exit(1);
}

static void dief(const char *fmt, const char *a) {
	if (term_color_enabled_stderr())
		fprintf(stderr, "%s%s%s ", FG_RED, "carbide:", SGR_RESET);
	fprintf(stderr, fmt, a);
	fputc('\n', stderr);
	exit(1);
}

static void dief_rc(int rc, const char *cmd) {
	char msg[256];
	if (!cmd || !*cmd)
		snprintf(msg, sizeof(msg), "default command failed (rc=%d)", rc);
	else
		snprintf(msg, sizeof(msg), "command '%s' failed (rc=%d)", cmd, rc);
	dief("%s", msg);
}

static void color_fprintf_tag(FILE *f, const char *tag, const char *color) {
	int use_color = (f == stderr) ? term_color_enabled_stderr() : term_color_enabled_stdout();
	if (use_color) {
		fprintf(f, "%s[%s]%s ", color, tag, SGR_RESET);
	} else {
		fprintf(f, "[%s] ", tag);
	}
}

static int env_truthy(const char *v) {
	if (!v || !*v)
		return 0;

	if (strcmp(v, "1") == 0)
		return 1;

	char buf[8] = {0};
	size_t n = strlen(v);
	if (n > 7)
		n = 7;

	for (size_t i = 0; i < n; ++i)
		buf[i] = (char)tolower((unsigned char)v[i]);

	return (strcmp(buf, "true") == 0 || strcmp(buf, "yes") == 0 || strcmp(buf, "on") == 0);
}

static cb_term_color_level detect_color_level_from_env(void) {
	const char *colorterm = getenv("COLORTERM");
	const char *term = getenv("TERM");
	if (colorterm && (strstr(colorterm, "truecolor") || strstr(colorterm, "24bit")))
		return CB_TERM_COLOR_TRUECOLOR;

	if (term && strstr(term, "direct"))
		return CB_TERM_COLOR_TRUECOLOR;

	if (term && (strstr(term, "256color") || strstr(term, "xterm-256color") || strstr(term, "screen-256color")))
		return CB_TERM_COLOR_256;

	if (term && (strstr(term, "xterm") || strstr(term, "vt100") || strstr(term, "ansi") || strstr(term, "screen")))
		return CB_TERM_COLOR_BASIC;

	return CB_TERM_COLOR_NONE;
}

static void init_terminal_caps(cb_term_caps *caps) {
	memset(caps, 0, sizeof(*caps));
#if defined(_WIN32)
	caps->stdout_is_tty = (_isatty(1) != 0);
	caps->stderr_is_tty = (_isatty(2) != 0);
#else
	caps->stdout_is_tty = (isatty(1) != 0);
	caps->stderr_is_tty = (isatty(2) != 0);
#endif
	if (getenv("NO_COLOR")) {
		caps->color_level = CB_TERM_COLOR_NONE;
	} else {
		caps->color_level = detect_color_level_from_env();
	}

	if (env_truthy(getenv("CLICOLOR_FORCE")) || env_truthy(getenv("FORCE_COLOR"))) {
		if (caps->color_level == CB_TERM_COLOR_NONE)
			caps->color_level = CB_TERM_COLOR_BASIC;

		caps->use_color_stdout = true;
		caps->use_color_stderr = true;
	} else {
		const char *clic = getenv("CLICOLOR");
		if (clic && strcmp(clic, "0") == 0) {
			caps->color_level = CB_TERM_COLOR_NONE;
		}
	}

#if defined(_WIN32)
	if (caps->stdout_is_tty || caps->stderr_is_tty) {
		HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);
		HANDLE herr = GetStdHandle(STD_ERROR_HANDLE);
		DWORD mode = 0;
		if (hout && GetConsoleMode(hout, &mode)) {
			SetConsoleMode(hout, mode | 0x0004);
		}
		if (herr && GetConsoleMode(herr, &mode)) {
			SetConsoleMode(herr, mode | 0x0004);
		}
		if (caps->color_level == CB_TERM_COLOR_NONE && (caps->stdout_is_tty || caps->stderr_is_tty))
			caps->color_level = CB_TERM_COLOR_BASIC;
	}
#endif

	if (!caps->use_color_stdout)
		caps->use_color_stdout = (caps->color_level != CB_TERM_COLOR_NONE) && caps->stdout_is_tty;
	if (!caps->use_color_stderr)
		caps->use_color_stderr = (caps->color_level != CB_TERM_COLOR_NONE) && caps->stderr_is_tty;
}

static char *scratch(void) {
	enum { N = 8 };
	static char bufs[N][PATH_MAX];
	static unsigned idx;
	char *b = bufs[idx++ % N];
	b[0] = 0;
	return b;
}
static inline int is_sep(char c) { return c == CB_PATH_SEP || c == CB_OTHER_SEP; }

static size_t prefix_len(const char *p) {
#if defined(_WIN32)
	if (p[0] == '\\' && p[1] == '\\') {
		const char *s = p + 2, *slash = s;
		while (*slash && !is_sep(*slash))
			slash++;
		if (!*slash)
			return (size_t)(slash - p);
		slash++;
		while (*slash && !is_sep(*slash))
			slash++;
		return (size_t)(slash - p);
	}
	if (((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':')
		return is_sep(p[2]) ? 3u : 2u;
	if (is_sep(p[0]))
		return 1u;
	return 0u;
#else
	return (p[0] == '/') ? 1u : 0u;
#endif
}

CB_API void cb_require_min_version(int M, int m, int p) {
	(void)p;
	if (M > CB_API_VERSION_MAJOR || (M == CB_API_VERSION_MAJOR && m > CB_API_VERSION_MINOR))
		die("recipe requires a newer Carbide driver");
}

CB_API void cb_log_verbose(const char *fmt, ...) {
	if (!cb_is_verbose())
		return;

	color_fprintf_tag(stderr, "VERBOSE", FG_YELLOW);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

CB_API void cb_log_info(const char *fmt, ...) {
	color_fprintf_tag(stderr, "INFO", FG_CYAN);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

CB_API void cb_log_warn(const char *fmt, ...) {
	color_fprintf_tag(stderr, "WARN", FG_MAGENTA);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

CB_API void cb_log_error(const char *fmt, ...) {
	color_fprintf_tag(stderr, "ERROR", FG_RED);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

CB_API const char *cb_norm(const char *p) {
	if (!p || !*p)
		return "";
	char *out = scratch();

	char tmp[PATH_MAX];
	size_t n = 0;
	for (const char *s = p; *s && n + 1 < sizeof(tmp); ++s) {
		char c = *s;
		if (is_sep(c))
			c = CB_PATH_SEP;
		if (n > 0 && tmp[n - 1] == CB_PATH_SEP && c == CB_PATH_SEP)
			continue;
		tmp[n++] = c;
	}
	tmp[n] = 0;

	size_t pref = prefix_len(tmp);
	const char *scan = tmp + pref;
	size_t stack_idx = 0;
	size_t comp_pos[PATH_MAX / 2];

	memcpy(out, tmp, pref);
	size_t out_len = pref;

#if defined(_WIN32)
	int drive_only = (pref == 2 && tmp[1] == ':');
#else
	int drive_only = 0;
#endif

	while (*scan) {
		while (*scan == CB_PATH_SEP)
			scan++;
		if (!*scan)
			break;

		const char *start = scan;
		while (*scan && *scan != CB_PATH_SEP)
			scan++;
		size_t clen = (size_t)(scan - start);

		if (clen == 1 && start[0] == '.')
			continue;
		if (clen == 2 && start[0] == '.' && start[1] == '.') {
			if (stack_idx > 0) {
				out_len = comp_pos[--stack_idx];
				out[out_len] = 0;
			} else if (pref > 0 && !drive_only) {
			} else {
				if (out_len && out[out_len - 1] != CB_PATH_SEP)
					out_len++, out[out_len - 1] = CB_PATH_SEP;
				comp_pos[stack_idx++] = out_len;
				if (out_len + 2 + 1 >= PATH_MAX) {
					out[0] = 0;
					return out;
				}
				out[out_len++] = '.';
				out[out_len++] = '.';
				out[out_len] = 0;
			}
			continue;
		}

		if (out_len && out[out_len - 1] != CB_PATH_SEP)
			out[out_len++] = CB_PATH_SEP;
		comp_pos[stack_idx++] = out_len;
		if (out_len + clen + 1 >= PATH_MAX) {
			out[0] = 0;
			return out;
		}
		memcpy(out + out_len, start, clen);
		out_len += clen;
		out[out_len] = 0;
	}

	if (out_len == 0)
		strcpy(out, ".");
	if (out_len > pref && out[out_len - 1] == CB_PATH_SEP)
		out[--out_len] = 0;
	return out;
}

CB_API const char *cb_join(const char *a, const char *b) {
	if (!b || !*b)
		return cb_norm(a ? a : "");
	if (!a || !*a)
		return cb_norm(b);
	if (prefix_len(b) > 0) {
#if defined(_WIN32)
		if (!(prefix_len(b) == 2 && b[1] == ':'))
			return cb_norm(b);
#else
		return cb_norm(b);
#endif
	}
	char *buf = scratch();
	size_t alen = strlen(a), blen = strlen(b);
	if (alen + 1 + blen + 1 >= PATH_MAX) {
		buf[0] = 0;
		return buf;
	}
	memcpy(buf, a, alen);
	size_t n = alen;
	if (n && !is_sep(buf[n - 1]))
		buf[n++] = CB_PATH_SEP;
	memcpy(buf + n, b, blen);
	n += blen;
	buf[n] = 0;
	return cb_norm(buf);
}

CB_API const char *cb_rel_to_workspace(const char *abs) {
	const char *root = g_ctx_singleton ? g_ctx_singleton->workspace_root : "";
	size_t rl = root ? strlen(root) : 0;
	if (rl && strncmp(abs, root, rl) == 0) {
		const char *p = abs + rl;
		if (*p == CB_PATH_SEP)
			++p;
		return p;
	}
	return abs;
}

CB_API const char *cg_abspath(const char *p) {
	if (!p || !*p) {
#if defined(_WIN32)
		DWORD n = GetCurrentDirectoryA(0, CB_NULL);
		char *tmp = scratch();
		if (n == 0 || n >= PATH_MAX) {
			tmp[0] = 0;
			return tmp;
		}
		GetCurrentDirectoryA(PATH_MAX, tmp);
		return cb_norm(tmp);
#else
		char *tmp = scratch();
		if (!getcwd(tmp, PATH_MAX)) {
			tmp[0] = 0;
			return tmp;
		}
		return cb_norm(tmp);
#endif
	}

#if defined(_WIN32)
	char buf[PATH_MAX];
	DWORD n = GetFullPathNameA(p, PATH_MAX, buf, CB_NULL);
	if (n == 0 || n >= PATH_MAX) {
		char cwd[PATH_MAX] = {0};
		GetCurrentDirectoryA(PATH_MAX, cwd);
		const char *j = cb_join(cwd, p);
		return cb_norm(j);
	}
	char *out = scratch();
	strncpy(out, buf, PATH_MAX);
	out[PATH_MAX - 1] = 0;
	return cb_norm(out);

#else
	{
		char *rp = realpath(p, CB_NULL);
		if (rp) {
			char *out = scratch();
			strncpy(out, rp, PATH_MAX);
			out[PATH_MAX - 1] = 0;
			free(rp);
			return cb_norm(out);
		}
	}

	char cwd[PATH_MAX];
	if (!getcwd(cwd, sizeof(cwd))) {
		return cb_norm(p);
	}
	const char *j = (prefix_len(p) > 0) ? p : cb_join(cwd, p);
	return cb_norm(j);
#endif
}

CB_API bool cb_file_exists(const char *path) {
#if defined(_WIN32)
	DWORD attrs = GetFileAttributesA(path);
	return (attrs != INVALID_FILE_ATTRIBUTES) && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
#else
	return access(path, F_OK) == 0;
#endif
}
CB_API bool cb_is_dir(const char *path) {
#if defined(_WIN32)
	DWORD attrs = GetFileAttributesA(path);
	return (attrs != INVALID_FILE_ATTRIBUTES) && (attrs & FILE_ATTRIBUTE_DIRECTORY);
#else
	struct stat st;
	return (stat(path, &st) == 0) && S_ISDIR(st.st_mode);
#endif
}

CB_API const char *cb_mkdir_p(const char *path) {
	if (!path || !*path)
		return CB_NULL;
	const char *norm = cb_norm(path);
	if (!*norm)
		return CB_NULL;
	if (cb_is_dir(norm))
		return norm;

	char cur[PATH_MAX];
	memcpy(cur, norm, strlen(norm) + 1);
	size_t i = prefix_len(cur);
	if (!i && cur[0] == 0)
		return CB_NULL;

	for (size_t j = i; cur[j]; ++j) {
		if (cur[j] == CB_PATH_SEP) {
			cur[j] = 0;
			if (cur[0] && !cb_is_dir(cur)) {
#if defined(_WIN32)
				if (!CreateDirectoryA(cur, CB_NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
					return CB_NULL;
#else
				if (mkdir(cur, 0775) != 0 && errno != EEXIST)
					return CB_NULL;
#endif
			}
			cur[j] = CB_PATH_SEP;
		}
	}
	if (!cb_is_dir(cur)) {
#if defined(_WIN32)
		if (!CreateDirectoryA(cur, CB_NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
			return CB_NULL;
#else
		if (mkdir(cur, 0775) != 0 && errno != EEXIST)
			return CB_NULL;
#endif
	}
	return norm;
}

CB_API const char *cb_write_text(const char *path, const char *content) {
	FILE *f = fopen(path, "wb");
	if (!f)
		return CB_NULL;
	if (content && *content)
		fwrite(content, 1, strlen(content), f);
	fclose(f);
	return cb_norm(path);
}

CB_API void cb_strlist_init(cb_strlist *l) {
	l->data = CB_NULL;
	l->len = l->cap = 0;
}
CB_API void cb_strlist_free(cb_strlist *l) {
	if (!l)
		return;
	for (size_t i = 0; i < l->len; ++i)
		free((void *)l->data[i]);
	free(l->data);
	l->data = CB_NULL;
	l->len = l->cap = 0;
}
CB_API void cb_strlist_push(cb_strlist *l, const char *s) {
	if (l->len == l->cap) {
		l->cap = l->cap ? l->cap * 2 : 8;
		l->data = (const char **)realloc(l->data, l->cap * sizeof(char *));
		if (!l->data)
			die("oom");
	}
	size_t n = strlen(s ? s : "");
	char *dup = (char *)malloc(n + 1);
	if (!dup)
		die("oom");
	memcpy(dup, s ? s : "", n + 1);
	l->data[l->len++] = dup;
}

static bool ends_with(const char *s, const char *suf) {
	if (!suf || !*suf)
		return 1;

	size_t ls = strlen(s), lu = strlen(suf);
	return (ls >= lu) && (strcmp(s + (ls - lu), suf) == 0);
}

CB_API void cb_glob(const char *pattern, cb_strlist *out) {
	if (!pattern || !*pattern || !out)
		return;
#if defined(_WIN32)
	WIN32_FIND_DATAA f;
	HANDLE h = FindFirstFileA(pattern, &f);
	if (h == INVALID_HANDLE_VALUE) {
		if (cb_file_exists(pattern))
			cb_strlist_push(out, pattern);
		return;
	}
	char dir[PATH_MAX] = {0};
	{
		char tmp[PATH_MAX];
		strncpy(tmp, pattern, sizeof(tmp));
		tmp[sizeof(tmp) - 1] = 0;
		for (int i = (int)strlen(tmp) - 1; i >= 0; --i) {
			if (is_sep(tmp[i])) {
				tmp[i] = 0;
				break;
			}
		}
		strncpy(dir, tmp, sizeof(dir));
	}
	do {
		if (!(f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
			const char *p = dir[0] ? cb_join(dir, f.cFileName) : f.cFileName;
			cb_strlist_push(out, p);
		}
	} while (FindNextFileA(h, &f));
	FindClose(h);
#else
	glob_t g;
	memset(&g, 0, sizeof(g));
	if (glob(pattern, 0, CB_NULL, &g) == 0) {
		for (size_t i = 0; i < g.gl_pathc; i++)
			cb_strlist_push(out, g.gl_pathv[i]);
	} else if (cb_file_exists(pattern)) {
		cb_strlist_push(out, pattern);
	}
	globfree(&g);
#endif
}

static void rglob_impl(const char *root, const char *suffix, cb_strlist *out) {
#if defined(_WIN32)
	char pattern[PATH_MAX];
	snprintf(pattern, sizeof(pattern), "%s\\*", root);
	WIN32_FIND_DATAA f;
	HANDLE h = FindFirstFileA(pattern, &f);
	if (h == INVALID_HANDLE_VALUE) {
		return;
	}
	do {
		const char *name = f.cFileName;
		if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
			continue;
		char full[PATH_MAX];
		snprintf(full, sizeof(full), "%s\\%s", root, name);
		if (f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			rglob_impl(full, suffix, out);
		} else {
			if (ends_with(full, suffix)) {
				cb_strlist_push(out, full);
			}
		}
	} while (FindNextFileA(h, &f));
	FindClose(h);
#else
	DIR *d = opendir(root);
	if (!d) {
		return;
	}
	struct dirent *ent;
	while ((ent = readdir(d))) {
		const char *name = ent->d_name;
		if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
			continue;

		char full[PATH_MAX];
		size_t n = snprintf(full, sizeof(full), "%s/%s", root, name);
		if (n >= sizeof(full))
			continue;

		struct stat st;
		if (lstat(full, &st) != 0) {
			continue;
		}
		if (S_ISDIR(st.st_mode)) {
			rglob_impl(full, suffix, out);
		} else if (S_ISREG(st.st_mode)) {
			if (ends_with(full, suffix)) {
				cb_strlist_push(out, full);
			}
		}
	}
	closedir(d);
#endif
}

CB_API void cb_rglob(const char *root_dir, const char *suffix, cb_strlist *out) {
	if (!root_dir || !*root_dir || !out)
		return;

	char root[PATH_MAX];
	const char *norm = cb_norm(root_dir);
	strncpy(root, norm, sizeof(root));
	root[sizeof(root) - 1] = '\0';

	if (!cb_is_dir(root)) {
		return;
	}
	rglob_impl(root, suffix, out);
}

static int64_t file_mtime(const char *p) {
#if defined(_WIN32)
	WIN32_FILE_ATTRIBUTE_DATA fad;
	if (!GetFileAttributesExA(p, GetFileExInfoStandard, &fad))
		return 0;
	ULARGE_INTEGER t;
	t.LowPart = fad.ftLastWriteTime.dwLowDateTime;
	t.HighPart = fad.ftLastWriteTime.dwHighDateTime;
	return (int64_t)(t.QuadPart / 10000000ULL);
#else
	struct stat st;
	if (stat(p, &st) != 0)
		return 0;
	return (int64_t)st.st_mtime;
#endif
}
CB_API bool cb_needs_rebuild(const char *out, const char *const *inputs, size_t n_inputs) {
	if (!out || !cb_file_exists(out))
		return true;
	int64_t mo = file_mtime(out);
	for (size_t i = 0; i < n_inputs; ++i) {
		const char *in = inputs[i];
		if (!in || !cb_file_exists(in))
			continue;
		if (file_mtime(in) > mo)
			return true;
	}
	return false;
}

static void *xrealloc(void *p, size_t n) {
	void *q = realloc(p, n);
	if (!q) {
		free(p);
		die("oom");
	}
	return q;
}
static char *xstrdup(const char *s) {
	if (!s)
		return CB_NULL;
	size_t n = strlen(s) + 1;
	char *d = (char *)malloc(n);
	if (!d)
		die("oom");
	memcpy(d, s, n);
	return d;
}
static void argv_grow(cb_cmd *c, int extra) {
	int need = c->argc + extra + 1;
	if (need <= c->argv_cap)
		return;
	int cap = c->argv_cap ? c->argv_cap : 8;
	while (cap < need)
		cap *= 2;
	c->argv = (char **)xrealloc(c->argv, (size_t)cap * sizeof(char *));
	c->argv_cap = cap;
}
static void env_grow(cb_cmd *c, int extra) {
	int need = c->envc + extra;
	if (need <= c->env_cap)
		return;
	int cap = c->env_cap ? c->env_cap : 8;
	while (cap < need)
		cap *= 2;
	c->env = (cb_env_kv *)xrealloc(c->env, (size_t)cap * sizeof(cb_env_kv));
	c->env_cap = cap;
}

CB_API cb_cmd *cb_cmd_new(void) {
	cb_cmd *c = (cb_cmd *)calloc(1, sizeof(cb_cmd));
	c->inherit_env = true;
	argv_grow(c, 0);
	c->argv[0] = CB_NULL;
	return c;
}
CB_API void cb_cmd_free(cb_cmd *c) {
	if (!c)
		return;
	for (int i = 0; i < c->argc; i++)
		free(c->argv[i]);
	free(c->argv);
	for (int i = 0; i < c->envc; i++) {
		free(c->env[i].k);
		free(c->env[i].v);
	}
	free(c->env);
	free(c->cwd);
	free(c->in_path);
	free(c->out_path);
	free(c->err_path);
	free(c);
}
CB_API void cb_cmd_set_argv(cb_cmd *c, const char *const *argv, size_t argc) {
	if (!c)
		return;
	for (int i = 0; i < c->argc; i++)
		free(c->argv[i]);
	c->argc = 0;
	for (size_t i = 0; i < argc; i++) {
		argv_grow(c, 1);
		c->argv[c->argc++] = xstrdup(argv[i]);
	}
	c->argv[c->argc] = CB_NULL;
}
CB_API void cb_cmd_push_arg(cb_cmd *c, const char *s) {
	if (!c || !s)
		return;
	argv_grow(c, 1);
	c->argv[c->argc++] = xstrdup(s);
	c->argv[c->argc] = CB_NULL;
}
CB_API void cb_cmd_env(cb_cmd *c, const char *k, const char *v) {
	if (!c || !k)
		return;
	for (int i = 0; i < c->envc; i++)
		if (strcmp(c->env[i].k, k) == 0) {
			free(c->env[i].v);
			c->env[i].v = xstrdup(v ? v : "");
			return;
		}
	env_grow(c, 1);
	c->env[c->envc].k = xstrdup(k);
	c->env[c->envc].v = xstrdup(v ? v : "");
	c->envc++;
}
CB_API void cb_cmd_clear_env(cb_cmd *c) {
	if (!c)
		return;
	for (int i = 0; i < c->envc; i++) {
		free(c->env[i].k);
		free(c->env[i].v);
	}
	c->envc = 0;
	c->inherit_env = false;
}
CB_API void cb_cmd_inherit_env(cb_cmd *c, bool on) {
	if (c)
		c->inherit_env = on;
}
CB_API void cb_cmd_cwd(cb_cmd *c, const char *dir) {
	if (!c)
		return;
	free(c->cwd);
	c->cwd = dir ? xstrdup(dir) : CB_NULL;
}
CB_API void cb_cmd_stdio(cb_cmd *c, const char *in, const char *out, const char *err) {
	if (!c)
		return;
	free(c->in_path);
	free(c->out_path);
	free(c->err_path);
	c->in_path = in ? xstrdup(in) : CB_NULL;
	c->out_path = out ? xstrdup(out) : CB_NULL;
	c->err_path = err ? xstrdup(err) : CB_NULL;
}

#ifndef _WIN32
static int key_idx(char **arr, int cnt, const char *k) {
	size_t klen = strlen(k);
	for (int i = 0; i < cnt; i++) {
		const char *s = arr[i];
		const char *eq = s ? strchr(s, '=') : CB_NULL;
		size_t kk = eq ? (size_t)(eq - s) : strlen(s);
		if (kk == klen && strncmp(s, k, klen) == 0)
			return i;
	}
	return -1;
}
static char **build_envp_posix(const cb_cmd *c) {
	if (c->inherit_env && c->envc == 0)
		return CB_NULL;
	int parent = 0;
	if (c->inherit_env)
		for (char **p = __environ; p && *p; ++p)
			parent++;
	int cap = parent + c->envc + 8;
	char **envp = (char **)calloc((size_t)(cap + 1), sizeof(char *));
	if (!envp)
		return CB_NULL;
	int n = 0;
	if (c->inherit_env)
		for (char **p = __environ; p && *p; ++p)
			envp[n++] = strdup(*p);
	for (int i = 0; i < c->envc; i++) {
		const char *k = c->env[i].k ? c->env[i].k : "";
		const char *v = c->env[i].v ? c->env[i].v : "";
		size_t L = strlen(k) + 1 + strlen(v) + 1;
		char *kv = (char *)malloc(L);
		snprintf(kv, L, "%s=%s", k, v);
		int at = key_idx(envp, n, k);
		if (at >= 0) {
			free(envp[at]);
			envp[at] = kv;
		} else
			envp[n++] = kv;
	}
	envp[n] = CB_NULL;
	return envp;
}
static int open_redir(const char *path, int in) {
	if (!path)
		return -1;
	return in ? open(path, O_RDONLY) : open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
}
#endif

CB_API int cb_cmd_run(const cb_cmd *c, int *exit_code) {
	if (!c || c->argc <= 0 || !c->argv || !c->argv[0])
		return -1;
	if (exit_code)
		*exit_code = -1;
#if !defined(_WIN32)
	char **envp = build_envp_posix(c);
	pid_t pid = fork();
	if (pid < 0) {
		if (envp) {
			for (char **p = envp; *p; ++p)
				free(*p);
			free(envp);
		}
		return -1;
	}
	if (pid == 0) {
		if (c->cwd && chdir(c->cwd) != 0)
			_exit(127);
		int infd = open_redir(c->in_path, 1), outfd = open_redir(c->out_path, 0), errfd = open_redir(c->err_path, 0);
		if (c->in_path && (infd < 0 || dup2(infd, 0) < 0))
			_exit(127);
		if (c->out_path && (outfd < 0 || dup2(outfd, 1) < 0))
			_exit(127);
		if (c->err_path && (errfd < 0 || dup2(errfd, 2) < 0))
			_exit(127);
		if (infd >= 3)
			close(infd);
		if (outfd >= 3)
			close(outfd);
		if (errfd >= 3)
			close(errfd);
		signal(SIGPIPE, SIG_DFL);
	#if defined(__GLIBC__)
		extern int execvpe(const char *, char *const[], char *const[]);
		if (envp)
			execvpe(c->argv[0], c->argv, envp);
		else
			execvp(c->argv[0], c->argv);
	#else
		if (envp) {
			const char *prog = c->argv[0];
			if (strchr(prog, '/'))
				execve(prog, c->argv, envp);
			const char *PATH = "/usr/local/bin:/usr/bin:/bin";
			for (char **p = envp; *p; ++p)
				if (strncmp(*p, "PATH=", 5) == 0) {
					PATH = *p + 5;
					break;
				}
			char buf[PATH_MAX];
			const char *s = PATH;
			while (*s) {
				const char *col = strchr(s, ':');
				size_t L = col ? (size_t)(col - s) : strlen(s);
				if (L + 1 + strlen(prog) + 1 < sizeof(buf)) {
					memcpy(buf, s, L);
					buf[L] = '/';
					strcpy(buf + L + 1, prog);
					execve(buf, c->argv, envp);
				}
				if (!col)
					break;
				s = col + 1;
			}
			execve(prog, c->argv, envp);
		} else
			execvp(c->argv[0], c->argv);
	#endif
		_exit(127);
	}
	int status = 0;
	if (waitpid(pid, &status, 0) < 0) {
		if (envp) {
			for (char **p = envp; *p; ++p)
				free(*p);
			free(envp);
		}
		return -1;
	}
	if (exit_code) {
		if (WIFEXITED(status))
			*exit_code = WEXITSTATUS(status);
		else if (WIFSIGNALED(status))
			*exit_code = 128 + WTERMSIG(status);
		else
			*exit_code = -1;
	}
	if (envp) {
		for (char **p = envp; *p; ++p)
			free(*p);
		free(envp);
	}
	return 0;
#else
	auto needs_quote = [](const char *s) -> int {
		if (!*s)
			return 1;
		for (const char *p = s; *p; ++p)
			if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '"')
				return 1;
		return 0;
	};
	auto quote_arg = [&](const char *arg) -> char * {
		if (!arg)
			return _strdup("");
		if (!needs_quote(arg))
			return _strdup(arg);
		size_t len = strlen(arg), cap = len * 2 + 3;
		char *out = (char *)malloc(cap);
		if (!out)
			return CB_NULL;
		size_t n = 0;
		out[n++] = '"';
		size_t bs = 0;
		for (size_t i = 0; i < len; i++) {
			char c = arg[i];
			if (c == '\\') {
				bs++;
			} else if (c == '"') {
				while (bs--)
					out[n++] = '\\';
				out[n++] = '\\';
				out[n++] = '"';
				bs = 0;
			} else {
				while (bs--)
					out[n++] = '\\';
				out[n++] = c;
			}
			if (n + 4 >= cap) {
				cap *= 2;
				out = (char *)realloc(out, cap);
			}
		}
		while (bs--)
			out[n++] = '\\';
		out[n++] = '"';
		out[n] = 0;
		return out;
	};
	size_t cap = 0;
	char **q = (char **)calloc((size_t)c->argc, sizeof(char *));
	for (int i = 0; i < c->argc; i++) {
		q[i] = quote_arg(c->argv[i]);
		cap += strlen(q[i]) + 1;
	}
	char *utf8 = (char *)malloc(cap + 1);
	size_t n = 0;
	for (int i = 0; i < c->argc; i++) {
		size_t L = strlen(q[i]);
		memcpy(utf8 + n, q[i], L);
		n += L;
		if (i + 1 < c->argc)
			utf8[n++] = ' ';
	}
	utf8[n] = 0;
	for (int i = 0; i < c->argc; i++)
		free(q[i]);
	free(q);
	int wchars = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, CB_NULL, 0);
	wchar_t *cmdline = (wchar_t *)malloc((size_t)wchars * sizeof(wchar_t));
	MultiByteToWideChar(CP_UTF8, 0, utf8, -1, cmdline, wchars);
	free(utf8);

	wchar_t *cwdw = CB_NULL;
	if (c->cwd) {
		int m = MultiByteToWideChar(CP_UTF8, 0, c->cwd, -1, CB_NULL, 0);
		cwdw = (wchar_t *)malloc((size_t)m * sizeof(wchar_t));
		MultiByteToWideChar(CP_UTF8, 0, c->cwd, -1, cwdw, m);
	}

	wchar_t *env_block = CB_NULL;
	if (!c->inherit_env || c->envc > 0) {
		typedef struct {
			char *kv;
		} kvs;
		kvs *arr = CB_NULL;
		int nkv = 0, capkv = 0;
	#define PUSH(s)                                                                                                    \
		do {                                                                                                           \
			if (nkv == capkv) {                                                                                        \
				capkv = capkv ? capkv * 2 : 32;                                                                        \
				arr = (kvs *)realloc(arr, (size_t)capkv * sizeof(kvs));                                                \
			}                                                                                                          \
			arr[nkv++].kv = _strdup(s);                                                                                \
		} while (0)
		if (c->inherit_env) {
			LPWCH blk = GetEnvironmentStringsW();
			if (blk) {
				const wchar_t *p = blk;
				while (*p) {
					size_t wl = wcslen(p);
					int bytes = WideCharToMultiByte(CP_UTF8, 0, p, (int)wl, CB_NULL, 0, CB_NULL, CB_NULL);
					char *u = (char *)malloc((size_t)bytes + 1);
					WideCharToMultiByte(CP_UTF8, 0, p, (int)wl, u, bytes, CB_NULL, CB_NULL);
					u[bytes] = 0;
					if (strchr(u, '='))
						PUSH(u);
					free(u);
					p += wl + 1;
				}
				FreeEnvironmentStringsW(blk);
			}
		}
		for (int i = 0; i < c->envc; i++) {
			const char *k = c->env[i].k ? c->env[i].k : "";
			const char *v = c->env[i].v ? c->env[i].v : "";
			size_t L = strlen(k) + 1 + strlen(v) + 1;
			char *kv = (char *)malloc(L);
			snprintf(kv, L, "%s=%s", k, v);
			size_t klen = strlen(k);
			int replaced = 0;
			for (int j = 0; j < nkv; j++) {
				const char *s = arr[j].kv;
				const char *eq = strchr(s, '=');
				size_t kk = eq ? (size_t)(eq - s) : strlen(s);
				if (kk == klen && strncmp(s, k, klen) == 0) {
					free(arr[j].kv);
					arr[j].kv = kv;
					replaced = 1;
					break;
				}
			}
			if (!replaced)
				PUSH(kv);
		}
		size_t wtot = 1;
		for (int i = 0; i < nkv; i++) {
			int m = MultiByteToWideChar(CP_UTF8, 0, arr[i].kv, -1, CB_NULL, 0);
			wchar_t *w = (wchar_t *)malloc((size_t)m * sizeof(wchar_t));
			MultiByteToWideChar(CP_UTF8, 0, arr[i].kv, -1, w, m);
			wtot += wcslen(w) + 1;
			free(w);
		}
		env_block = (wchar_t *)calloc(wtot, sizeof(wchar_t));
		size_t off = 0;
		for (int i = 0; i < nkv; i++) {
			int m = MultiByteToWideChar(CP_UTF8, 0, arr[i].kv, -1, CB_NULL, 0);
			wchar_t *w = (wchar_t *)malloc((size_t)m * sizeof(wchar_t));
			MultiByteToWideChar(CP_UTF8, 0, arr[i].kv, -1, w, m);
			size_t wl = wcslen(w);
			memcpy(env_block + off, w, (wl + 1) * sizeof(wchar_t));
			off += wl + 1;
			free(w);
		}
		for (int i = 0; i < nkv; i++)
			free(arr[i].kv);
		free(arr);
	}
	SECURITY_ATTRIBUTES sa = {sizeof(sa), CB_NULL, TRUE};
	HANDLE hIn = CB_NULL, hOut = CB_NULL, hErr = CB_NULL;
	auto widen = [&](const char *s) -> wchar_t * {
		if (!s)
			return CB_NULL;
		int m = MultiByteToWideChar(CP_UTF8, 0, s, -1, CB_NULL, 0);
		wchar_t *w = (wchar_t *)malloc((size_t)m * sizeof(wchar_t));
		MultiByteToWideChar(CP_UTF8, 0, s, -1, w, m);
		return w;
	};
	if (c->in_path) {
		wchar_t *p = widen(c->in_path);
		hIn = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, CB_NULL);
		free(p);
		if (hIn == INVALID_HANDLE_VALUE) {
			if (env_block)
				free(env_block);
			if (cwdw)
				free(cwdw);
			free(cmdline);
			return -1;
		}
		SetHandleInformation(hIn, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
	}
	if (c->out_path) {
		wchar_t *p = widen(c->out_path);
		hOut = CreateFileW(p, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, CB_NULL);
		free(p);
		if (hOut == INVALID_HANDLE_VALUE) {
			if (hIn)
				CloseHandle(hIn);
			if (env_block)
				free(env_block);
			if (cwdw)
				free(cwdw);
			free(cmdline);
			return -1;
		}
		SetHandleInformation(hOut, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
	}
	if (c->err_path) {
		wchar_t *p = widen(c->err_path);
		hErr = CreateFileW(p, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, CB_NULL);
		free(p);
		if (hErr == INVALID_HANDLE_VALUE) {
			if (hIn)
				CloseHandle(hIn);
			if (hOut)
				CloseHandle(hOut);
			if (env_block)
				free(env_block);
			if (cwdw)
				free(cwdw);
			free(cmdline);
			return -1;
		}
		SetHandleInformation(hErr, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
	}
	STARTUPINFOW si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	BOOL inherit = FALSE;
	if (hIn || hOut || hErr) {
		si.dwFlags |= STARTF_USESTDHANDLES;
		si.hStdInput = hIn ? hIn : GetStdHandle(STD_INPUT_HANDLE);
		si.hStdOutput = hOut ? hOut : GetStdHandle(STD_OUTPUT_HANDLE);
		si.hStdError = hErr ? hErr : GetStdHandle(STD_ERROR_HANDLE);
		inherit = TRUE;
	}
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	BOOL ok = CreateProcessW(CB_NULL, cmdline, CB_NULL, CB_NULL, inherit, 0, env_block, cwdw, &si, &pi);
	if (hIn)
		CloseHandle(hIn);
	if (hOut)
		CloseHandle(hOut);
	if (hErr)
		CloseHandle(hErr);
	if (env_block)
		free(env_block);
	if (cwdw)
		free(cwdw);
	free(cmdline);
	if (!ok)
		return -1;
	WaitForSingleObject(pi.hProcess, INFINITE);
	DWORD code = 0;
	GetExitCodeProcess(pi.hProcess, &code);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	if (exit_code)
		*exit_code = (int)code;
	return 0;
#endif
}

typedef struct handler_node {
	char *name;
	char *help;
	cb_cmd_handler_fn fn;
	struct handler_node *next;
} handler_node;
static handler_node *g_handlers = CB_NULL;

CB_API void cb_register_cmd(const char *name, cb_cmd_handler_fn fn, const char *help) {
	if (!name || !*name || !fn)
		return;
	handler_node *h = (handler_node *)calloc(1, sizeof(handler_node));
	h->name = xstrdup(name);
	h->help = help ? xstrdup(help) : xstrdup("");
	h->fn = fn;
	h->next = g_handlers;
	g_handlers = h;
}

CB_API void cb_set_default(cb_cmd_handler_fn fn, const char *help) {
	free(g_default_help);
	g_default_fn = fn;
	g_default_help = help ? xstrdup(help) : CB_NULL;
}

static handler_node *find_handler(const char *name) {
	for (handler_node *h = g_handlers; h; h = h->next)
		if (strcmp(h->name, name) == 0)
			return h;
	return CB_NULL;
}

static int builtin_help() {
	if (term_color_enabled_stderr()) {
		fprintf(stderr, "%sAvailable commands:%s\n", SGR_BOLD, SGR_RESET);
	} else {
		fprintf(stderr, "Available commands:\n");
	}
	if (g_default_fn) {
		if (term_color_enabled_stderr()) {
			fprintf(stderr, "  %s(default)%s         %s\n", FG_CYAN, SGR_RESET, g_default_help ? g_default_help : "");
		} else {
			fprintf(stderr, "  (default)         %s\n", g_default_help ? g_default_help : "");
		}
	}
	for (handler_node *h = g_handlers; h; h = h->next) {
		if (term_color_enabled_stderr()) {
			fprintf(stderr, "  %-16s %s%s%s\n", h->name, FG_DIM, h->help ? h->help : "", SGR_RESET);
		} else {
			fprintf(stderr, "  %-16s %s\n", h->name, h->help ? h->help : "");
		}
	}
	return 0;
}

CB_API int cb_dispatch(cb_context *ctx) {
	const char *cmd = ctx->args.cmd;

	if (!cmd || !*cmd) {
		if (g_default_fn) {
			return g_default_fn();
		}
		if (term_color_enabled_stderr()) {
			color_fprintf_tag(stderr, "ERROR", FG_RED);
			fprintf(stderr, "no command given. Try 'help'.\n");
		} else {
			cb_log_error("no command given. Try 'help'.");
		}
		return 2;
	}

	handler_node *h = find_handler(cmd);
	if (!h) {
		if (term_color_enabled_stderr()) {
			color_fprintf_tag(stderr, "ERROR", FG_RED);
			fprintf(stderr, "unknown command '%s'. Try 'help'.\n", cmd);
		} else {
			cb_log_error("unknown command '%s'. Try 'help'.", cmd);
		}
		return 2;
	}
	return h->fn();
}

CB_API cb_context *cb_ctx(void) { return g_ctx_singleton; }
CB_API const char *cb_workspace_root(void) { return g_ctx_singleton ? g_ctx_singleton->workspace_root : ""; }
CB_API const char *cb_out_root(void) { return g_ctx_singleton ? g_ctx_singleton->out_root : ""; }
CB_API const char *cb_tool_root(void) { return g_ctx_singleton ? g_ctx_singleton->tool_root : ""; }

static char *sdup(const char *s) {
	size_t n = strlen(s) + 1;
	char *d = (char *)malloc(n);
	if (!d)
		die("oom");
	memcpy(d, s, n);
	return d;
}

CB_API cb_context *cb_init(int argc, char **argv, cb_args *out_args) {
	cb_context *ctx = (cb_context *)calloc(1, sizeof(*ctx));
	if (!ctx)
		die("oom");

#if defined(_WIN32)
	char cwdbuf[MAX_PATH];
	(void)GetCurrentDirectoryA(MAX_PATH, cwdbuf);
	ctx->workspace_root = sdup(cb_norm(cwdbuf));
#else
	char cwdbuf[PATH_MAX];
	if (!getcwd(cwdbuf, sizeof(cwdbuf)))
		die("getcwd failed");
	ctx->workspace_root = sdup(cb_norm(cwdbuf));
#endif

	const char *out_dir_rel = ".carbide/out";
	cb_mkdir_p(".carbide");
	cb_mkdir_p(out_dir_rel);
	ctx->out_root = sdup(cb_norm(out_dir_rel));
	ctx->tool_root =
#if defined(_WIN32)
		sdup("C:\\Program Files\\Carbide");
#else
		sdup("/usr/local");
#endif

	cb_args A;
	memset(&A, 0, sizeof(A));
	A.workspace_root = ctx->workspace_root;
	A.out_root = ctx->out_root;
	A.tool_root = ctx->tool_root;

	int i = 1;
	for (; i < argc; ++i) {
		const char *s = argv[i];
		if (s[0] == '-') {
			if (strcmp(s, "-v") == 0 || strcmp(s, "--verbose") == 0) {
				A.verbose = true;
				continue;
			}
			if (strcmp(s, "--") == 0) {
				i++;
				break;
			}
			cb_log_warn("unknown flag '%s' (ignored)", s);
		} else
			break;
	}
	if (i < argc) {
		A.cmd = argv[i++];
		A.cmd_argv = (const char *const *)&argv[i];
		A.cmd_argc = (size_t)(argc - i);
	}
	ctx->args = A;
	g_ctx_singleton = ctx;
	if (out_args)
		*out_args = A;

	init_terminal_caps(&ctx->term);

	cb_register_cmd("help", builtin_help, "List available commands");
	return ctx;
}

CB_API int cb_finish(cb_context *ctx) {
	if (!ctx)
		return 0;
	if (ctx != g_ctx_singleton)
		return 0;

	for (handler_node *h = g_handlers; h;) {
		handler_node *n = h->next;
		free(h->name);
		free(h->help);
		free(h);
		h = n;
	}
	g_handlers = CB_NULL;

	free((void *)ctx->workspace_root);
	free((void *)ctx->out_root);
	free((void *)ctx->tool_root);
	g_ctx_singleton = CB_NULL;
	free(ctx);
	return 0;
}

#if defined(_WIN32)
typedef struct {
	HMODULE h;
} dylib_t;
static dylib_t dylib_open(const char *p) {
	dylib_t d = {0};
	d.h = LoadLibraryA(p);
	if (!d.h)
		die("LoadLibrary failed");
	return d;
}
static void *dylib_symbol(dylib_t *d, const char *n) { return (void *)GetProcAddress(d->h, n); }
static void dylib_close(dylib_t *d) {
	if (d->h)
		FreeLibrary(d->h);
}
static const char *shared_ext(void) { return ".dll"; }
#else
typedef struct {
	void *h;
} dylib_t;
static dylib_t dylib_open(const char *p) {
	dylib_t d = {0};
	d.h = dlopen(p, RTLD_NOW | RTLD_LOCAL);
	if (!d.h)
		dief("dlopen failed: %s", dlerror());
	return d;
}
static void *dylib_symbol(dylib_t *d, const char *n) { return dlsym(d->h, n); }
static void dylib_close(dylib_t *d) {
	if (d->h)
		dlclose(d->h);
}
	#if defined(__APPLE__)
static const char *shared_ext(void) { return ".dylib"; }
	#else
static const char *shared_ext(void) { return ".so"; }
	#endif
#endif

typedef void (*carbide_recipe_init_fn)(cb_context *);

typedef enum { CC_NONE, CC_MSVC, CC_CLANG_CL, CC_CLANG, CC_GCC } cc_kind;
typedef struct {
	cc_kind kind;
	char *path;
} compiler_t;

static int on_path(const char *exe, char *buf, size_t bufsz) {
#if defined(_WIN32)
	DWORD r = SearchPathA(CB_NULL, exe, ".exe", (DWORD)bufsz, buf, CB_NULL);
	return r != 0 && r < bufsz;
#else
	const char *PATH = getenv("PATH");
	if (!PATH || !*PATH)
		return 0;
	char tmp[PATH_MAX];
	strncpy(tmp, PATH, sizeof(tmp));
	tmp[sizeof(tmp) - 1] = 0;
	for (char *tok = strtok(tmp, ":"); tok; tok = strtok(CB_NULL, ":")) {
		const char *p = cb_join(tok, exe);
		if (cb_file_exists(p)) {
			strncpy(buf, p, bufsz);
			buf[bufsz - 1] = 0;
			return 1;
		}
	}
	return 0;
#endif
}

static compiler_t discover_compiler(void) {
	compiler_t c = {CC_NONE, CB_NULL};
#if defined(_WIN32)
	char buf[PATH_MAX];
	if (on_path("cl.exe", buf, sizeof(buf))) {
		c.kind = CC_MSVC;
		c.path = sdup(buf);
		return c;
	}
	if (on_path("clang-cl.exe", buf, sizeof(buf))) {
		c.kind = CC_CLANG_CL;
		c.path = sdup(buf);
		return c;
	}
	if (on_path("clang.exe", buf, sizeof(buf))) {
		c.kind = CC_CLANG;
		c.path = sdup(buf);
		return c;
	}
	if (on_path("gcc.exe", buf, sizeof(buf))) {
		c.kind = CC_GCC;
		c.path = sdup(buf);
		return c;
	}
	die("no C compiler found (install MSVC/Clang/GCC or set PATH)");
#else
	char buf[PATH_MAX];
	if (on_path("cc", buf, sizeof(buf))) {
		c.kind = CC_GCC;
		c.path = sdup(buf);
		return c;
	}
	if (on_path("clang", buf, sizeof(buf))) {
		c.kind = CC_CLANG;
		c.path = sdup(buf);
		return c;
	}
	if (on_path("gcc", buf, sizeof(buf))) {
		c.kind = CC_GCC;
		c.path = sdup(buf);
		return c;
	}
	die("no C compiler found (install clang/gcc or set PATH)");
#endif
	return (compiler_t){};
}

static const char *stamp_path(void) { return cb_join(".carbide", "Carbidefile.stamp"); }

static const char *out_so_path(void) {
	char *b = scratch();
	snprintf(b, PATH_MAX, "%s%s", cb_join(".carbide", "Carbidefile"), shared_ext());
	return b;
}

static uint64_t fnv1a64(const void *buf, size_t n, uint64_t seed) {
	const unsigned char *p = (const unsigned char *)buf;
	uint64_t h = seed ? seed : 1469598103934665603ULL; // offset basis
	const uint64_t prime = 1099511628211ULL;
	for (size_t i = 0; i < n; ++i) {
		h ^= (uint64_t)p[i];
		h *= prime;
	}
	return h;
}

static uint64_t hash_file(const char *path, uint64_t seed) {
	FILE *f = fopen(path, "rb");
	if (!f)
		return seed;
	unsigned char buf[64 * 1024];
	size_t r;
	while ((r = fread(buf, 1, sizeof(buf), f)) > 0)
		seed = fnv1a64(buf, r, seed);
	fclose(f);
	return seed;
}

static void hex64(uint64_t v, char out[17]) {
	static const char hexd[] = "0123456789abcdef";
	for (int i = 0; i < 16; ++i) {
		int sh = (15 - i) * 4;
		out[i] = hexd[(v >> sh) & 0xF];
	}
	out[16] = 0;
}

static void dirname_into(const char *path, char *out, size_t outsz) {
	if (!path || !*path) {
		if (outsz)
			out[0] = 0;
		return;
	}
	size_t n = strlen(path);
	size_t i = n;
	while (i > 0 && !is_sep(path[i - 1]))
		i--;
	if (i == 0) {
		strncpy(out, ".", outsz);
		out[outsz ? outsz - 1 : 0] = 0;
		return;
	}
	if (i >= outsz)
		i = outsz ? outsz - 1 : 0;
	memcpy(out, path, i);
	out[i] = 0;
}

static int visited_has(cb_strlist *v, const char *pnorm) {
	for (size_t i = 0; i < v->len; ++i)
		if (strcmp(v->data[i], pnorm) == 0)
			return 1;
	return 0;
}

static void fp_add_file_and_includes(const char *file_path, uint64_t *h, cb_strlist *visited) {
	if (!file_path || !*file_path)
		return;

	const char *normp = cb_norm(file_path);
	if (!*normp)
		return;
	if (visited_has(visited, normp))
		return;
	cb_strlist_push(visited, normp);

	*h = hash_file(normp, *h);

	FILE *f = fopen(normp, "rb");
	if (!f)
		return;

	char *buf = CB_NULL;
	size_t cap = 0, len = 0;
	char tmp[8192];
	size_t r;
	while ((r = fread(tmp, 1, sizeof(tmp), f)) > 0) {
		if (len + r + 1 > cap) {
			size_t newcap = cap ? cap * 2 : 16384;
			while (newcap < len + r + 1)
				newcap *= 2;
			char *nb = (char *)realloc(buf, newcap);
			if (!nb) {
				free(buf);
				fclose(f);
				die("oom");
			}
			buf = nb;
			cap = newcap;
		}
		memcpy(buf + len, tmp, r);
		len += r;
	}
	fclose(f);
	if (!buf)
		return;
	buf[len] = 0;

	int in_sl_comment = 0;
	int in_ml_comment = 0;
	int in_string = 0;
	int in_char = 0;
	int bol = 1;

	char incdir[PATH_MAX];
	dirname_into(normp, incdir, sizeof(incdir));

	for (size_t i = 0; i < len;) {
		char c = buf[i];

		if (c == '\n') {
			bol = 1;
			in_sl_comment = 0;
			i++;
			continue;
		}
		if (in_sl_comment) {
			i++;
			continue;
		}
		if (in_ml_comment) {
			if (c == '*' && i + 1 < len && buf[i + 1] == '/') {
				in_ml_comment = 0;
				i += 2;
			} else
				i++;
			continue;
		}
		if (in_string) {
			if (c == '\\' && i + 1 < len) {
				i += 2;
				continue;
			}
			if (c == '"') {
				in_string = 0;
				i++;
				continue;
			}
			i++;
			continue;
		}
		if (in_char) {
			if (c == '\\' && i + 1 < len) {
				i += 2;
				continue;
			}
			if (c == '\'') {
				in_char = 0;
				i++;
				continue;
			}
			i++;
			continue;
		}

		if (c == '/' && i + 1 < len && buf[i + 1] == '/') {
			in_sl_comment = 1;
			i += 2;
			continue;
		}
		if (c == '/' && i + 1 < len && buf[i + 1] == '*') {
			in_ml_comment = 1;
			i += 2;
			continue;
		}
		if (c == '"') {
			in_string = 1;
			i++;
			continue;
		}
		if (c == '\'') {
			in_char = 1;
			i++;
			continue;
		}

		if (bol && (c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v')) {
			i++;
			continue;
		}

		if (bol && c == '#') {
			size_t j = i + 1;
			while (j < len && (buf[j] == ' ' || buf[j] == '\t'))
				j++;
			const char kw[] = "include";
			size_t k = 0;
			while (j < len && k < sizeof(kw) - 1 && buf[j] == kw[k]) {
				j++;
				k++;
			}
			if (k == sizeof(kw) - 1) {
				while (j < len && (buf[j] == ' ' || buf[j] == '\t'))
					j++;
				if (j < len && buf[j] == '"') {
					j++;
					size_t start = j;
					while (j < len && buf[j] != '"')
						j++;
					if (j < len && buf[j] == '"') {
						size_t L = j - start;
						if (L > 0 && L < PATH_MAX - 1) {
							char rel[PATH_MAX];
							memcpy(rel, buf + start, L);
							rel[L] = 0;

							const char *joined = cb_join(incdir, rel);
							const char *norm_inc = cb_norm(joined);

							*h = fnv1a64(norm_inc, strlen(norm_inc), *h);

							fp_add_file_and_includes(norm_inc, h, visited);
						}
					}
				}
			}
			bol = 0;
			i++;
			continue;
		}

		bol = 0;
		i++;
	}

	free(buf);
}

static void compute_fp(const char *src, const compiler_t *cc, char out[33]) {
	uint64_t h = 0;

	uint32_t api[3] = {CB_API_VERSION_MAJOR, CB_API_VERSION_MINOR, CB_API_VERSION_PATCH};
	h = fnv1a64(api, sizeof(api), h);

	if (cc && cc->path)
		h = fnv1a64(cc->path, strlen(cc->path), h);
	const char *ext = shared_ext();
	h = fnv1a64(ext, strlen(ext), h);
#if defined(_WIN32)
	h = fnv1a64("win", 3, h);
#elif defined(__APPLE__)
	h = fnv1a64("mac", 3, h);
#else
	h = fnv1a64("nix", 3, h);
#endif
#if INTPTR_MAX == INT64_MAX
	h = fnv1a64("64", 2, h);
#else
	h = fnv1a64("32", 2, h);
#endif
	h = hash_file(src, h);

	cb_strlist visited; cb_strlist_init(&visited);
	fp_add_file_and_includes(src, &h, &visited);
	cb_strlist_free(&visited);

	uint64_t h2 = hash_file(src, h ^ 0x9e3779b97f4a7c15ULL);

	char a[17], b[17];
	hex64(h, a);
	hex64(h2, b);
	snprintf(out, 33, "%s%s", a, b);
}

static void write_stamp(const char *cc_path, const char *fp) {
	char buf[1024];
	snprintf(buf, sizeof(buf), "api=%d.%d.%d\ncc=%s\nfp=%s\n", CB_API_VERSION_MAJOR, CB_API_VERSION_MINOR,
			 CB_API_VERSION_PATCH, cc_path ? cc_path : "", fp ? fp : "");
	cb_write_text(stamp_path(), buf);
}

static void copy_line_value(char *dst, size_t dstsz, const char *src_after_eq) {
	if (!dstsz)
		return;

	size_t len = strcspn(src_after_eq, "\r\n");
	if (len >= dstsz)
		len = dstsz - 1;

	memcpy(dst, src_after_eq, len);
	dst[len] = '\0';
}

static int read_stamp(int *apiM, int *apim, int *apip, char *cc_path_out, size_t cc_sz, char *fp_out, size_t fp_sz) {
	FILE *f = fopen(stamp_path(), "r");
	if (!f)
		return 0;

	char line[1024];
	int got_api = 0, got_cc = 0, got_fp = 0;

	while (fgets(line, sizeof(line), f)) {
		if (!got_api && sscanf(line, "api=%d.%d.%d", apiM, apim, apip) == 3) {
			got_api = 1;
		} else if (!got_cc && strncmp(line, "cc=", 3) == 0) {
			copy_line_value(cc_path_out, cc_sz, line + 3);
			got_cc = 1;
		} else if (!got_fp && strncmp(line, "fp=", 3) == 0) {
			copy_line_value(fp_out, fp_sz, line + 3);
			got_fp = 1;
		}
	}
	fclose(f);
	return (got_api && got_cc && got_fp);
}

static int compile_carbidefile(const compiler_t *cc, const char *src, const char *so_out) {
	int exit_code = -1;
	cb_cmd *cm = cb_cmd_new();

#if defined(_WIN32)
	if (cc->kind == CC_MSVC || cc->kind == CC_CLANG_CL) {
		char oflag[PATH_MAX + 8];
		snprintf(oflag, sizeof(oflag), "/Fe:%s", so_out);
		cb_cmd_push_arg(cm, cc->path);
		cb_cmd_push_arg(cm, "/nologo");
		cb_cmd_push_arg(cm, "/LD");
		cb_cmd_push_arg(cm, "/Zi");
		cb_cmd_push_arg(cm, "/EHsc");
		cb_cmd_push_arg(cm, src);
		cb_cmd_push_arg(cm, oflag);
		cb_cmd_push_arg(cm, "/link");
		cb_cmd_push_arg(cm, "/DLL");
	} else {
		cb_cmd_push_arg(cm, cc->path);
		cb_cmd_push_arg(cm, "-shared");
		cb_cmd_push_arg(cm, "-O2");
		cb_cmd_push_arg(cm, "-g");
		cb_cmd_push_arg(cm, "-fPIC");
		cb_cmd_push_arg(cm, "-Wall");
		cb_cmd_push_arg(cm, "-Wextra");
		cb_cmd_push_arg(cm, "-o");
		cb_cmd_push_arg(cm, so_out);
		cb_cmd_push_arg(cm, src);
	}
#else
	cb_cmd_push_arg(cm, cc->path);
	#if defined(__APPLE__)
	cb_cmd_push_arg(cm, "-dynamiclib");
	cb_cmd_push_arg(cm, "-Wl,-export_dynamic");
	#else
	cb_cmd_push_arg(cm, "-shared");
	cb_cmd_push_arg(cm, "-rdynamic");
	#endif
	cb_cmd_push_arg(cm, "-O2");
	cb_cmd_push_arg(cm, "-g");
	cb_cmd_push_arg(cm, "-fPIC");
	cb_cmd_push_arg(cm, "-Wall");
	cb_cmd_push_arg(cm, "-Wextra");
	cb_cmd_push_arg(cm, "-o");
	cb_cmd_push_arg(cm, so_out);
	cb_cmd_push_arg(cm, src);
#endif
	int rc = cb_cmd_run(cm, &exit_code);
	cb_cmd_free(cm);
	if (rc != 0 || exit_code != 0) {
		if (term_color_enabled_stderr()) {
			fprintf(stderr, "%s%s%s recipe compilation failed (rc=%d exit=%d)\n", FG_RED, "carbide:", SGR_RESET, rc,
					exit_code);
		} else {
			fprintf(stderr, "carbide: recipe compilation failed (rc=%d exit=%d)\n", rc, exit_code);
		}
		return -1;
	}
	return 0;
}

int main(int argc, char **argv) {
	cb_args parsed;
	cb_context *ctx = cb_init(argc, argv, &parsed);
	(void)parsed;

	const char *src = "Carbidefile.c";
	if (!cb_file_exists(src))
		dief("could not find recipe file (%s) in current directory", src);

	compiler_t cc = discover_compiler();
	if (term_color_enabled_stderr()) {
		fprintf(stderr, "%s%s%s using compiler: %s\n", FG_CYAN, "carbide:", SGR_RESET, cc.path);
	} else {
		fprintf(stderr, "carbide: using compiler: %s\n", cc.path);
	}
	char *so_path = sdup(out_so_path());

	int need_build = 0;
	int64_t m_src = file_mtime(src);
	int64_t m_so = file_mtime(so_path);
	if (m_so == 0 || m_src > m_so)
		need_build = 1;

	char cur_fp[33];
	cur_fp[0] = 0;
	compute_fp(src, &cc, cur_fp);

	int apiM = 0, apim = 0, apip = 0;
	char prev_cc[PATH_MAX] = {0};
	char prev_fp[64] = {0};
	int have_stamp = read_stamp(&apiM, &apim, &apip, prev_cc, sizeof(prev_cc), prev_fp, sizeof(prev_fp));

	if (!have_stamp)
		need_build = 1;
	else {
		if (strcmp(prev_cc, cc.path ? cc.path : "") != 0)
			need_build = 1;
		if (apiM != CB_API_VERSION_MAJOR || apim != CB_API_VERSION_MINOR || apip != CB_API_VERSION_PATCH)
			need_build = 1;
		if (strcmp(prev_fp, cur_fp) != 0)
			need_build = 1;
	}

	if (need_build) {
		cb_mkdir_p(".carbide");
		if (compile_carbidefile(&cc, src, so_path) != 0) {
			cb_finish(ctx);
			free(cc.path);
			free(so_path);
			return 1;
		}
		write_stamp(cc.path, cur_fp);
	} else {
		cb_log_info("using cached Carbidefile (%s)", so_path);
	}

	dylib_t lib = dylib_open(so_path);
	carbide_recipe_init_fn entry = (carbide_recipe_init_fn)dylib_symbol(&lib, "carbide_recipe_main");
	if (!entry)
		die("could not locate symbol 'carbide_recipe_main'");

	entry(ctx);

	int rc = cb_dispatch(ctx);
	if (rc != 0)
		dief_rc(rc, ctx->args.cmd);

	dylib_close(&lib);
	cb_finish(ctx);
	return rc;
}
