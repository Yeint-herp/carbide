#ifndef CARBIDE_H
#define CARBIDE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
	#define CB_HAVE_C23 1
#else
	#define CB_HAVE_C23 0
#endif

#if defined(CB_API_IMPL)
	#if defined(_WIN32)
		#define CB_API __declspec(dllexport)
	#elif defined(__GNUC__) || defined(__clang__)
		#define CB_API __attribute__((visibility("default")))
	#else
		#define CB_API
	#endif
#else
	#if defined(_WIN32)
		#define CB_API __declspec(dllimport)
	#else
		#define CB_API
	#endif
#endif

#if defined(__GNUC__) || defined(__clang__)
	#define CB_NODISCARD __attribute__((warn_unused_result))
	#define CB_PRINTF(F, V) __attribute__((format(printf, F, V)))
#else
	#define CB_NODISCARD
	#define CB_PRINTF(F, V)
#endif

#if CB_HAVE_C23
	#define CB_NULL nullptr
#else
	#define CB_NULL NULL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CB_API_VERSION_MAJOR 2
#define CB_API_VERSION_MINOR 1
#define CB_API_VERSION_PATCH 2

CB_API void cb_require_min_version(int major, int minor, int patch);

CB_API void cb_log_verbose(const char *fmt, ...) CB_PRINTF(1, 2);
CB_API void cb_log_info(const char *fmt, ...) CB_PRINTF(1, 2);
CB_API void cb_log_warn(const char *fmt, ...) CB_PRINTF(1, 2);
CB_API void cb_log_error(const char *fmt, ...) CB_PRINTF(1, 2);

typedef enum cb_term_color_level {
	CB_TERM_COLOR_NONE = 0,
	CB_TERM_COLOR_BASIC = 1,
	CB_TERM_COLOR_256 = 2,
	CB_TERM_COLOR_TRUECOLOR = 3
} cb_term_color_level;

typedef struct cb_term_caps {
	int color_level;
	bool stdout_is_tty;
	bool stderr_is_tty;
	bool use_color_stdout;
	bool use_color_stderr;
} cb_term_caps;

typedef struct {
	const char *workspace_root;
	const char *out_root;
	const char *tool_root;

	const char *cmd;
	const char *const *cmd_argv;
	size_t cmd_argc;

	bool verbose;
} cb_args;

typedef struct cb_context {
	const char *workspace_root;
	const char *out_root;
	const char *tool_root;
	cb_args args;
	cb_term_caps term;
} cb_context;

typedef struct {
	const char **data;
	size_t len, cap;
} cb_strlist;

CB_API cb_context *cb_ctx(void);

CB_API void cb_strlist_init(cb_strlist *l);
CB_API void cb_strlist_free(cb_strlist *l);
CB_API void cb_strlist_push(cb_strlist *l, const char *s);

CB_API const char *cb_norm(const char *p);
CB_API const char *cb_join(const char *a, const char *b);
CB_API const char *cb_rel_to_workspace(const char *abs);
CB_API const char *cg_abspath(const char *p);

CB_API bool cb_file_exists(const char *path);
CB_API bool cb_is_dir(const char *path);
CB_API const char *cb_mkdir_p(const char *path);
CB_API const char *cb_write_text(const char *path, const char *content);

CB_API void cb_glob(const char *pattern, cb_strlist *out);
CB_API void cb_rglob(const char *root_dir, const char *suffix, cb_strlist *out);
CB_API bool cb_needs_rebuild(const char *out, const char *const *inputs, size_t n_inputs);

typedef struct cb_env_kv {
	char *k;
	char *v;
} cb_env_kv;

typedef struct cb_cmd {
	char **argv;
	int argc, argv_cap;
	cb_env_kv *env;
	int envc, env_cap;
	bool inherit_env;
	char *cwd;
	char *in_path, *out_path, *err_path;
} cb_cmd;

CB_API cb_cmd *cb_cmd_new(void);
CB_API void cb_cmd_free(cb_cmd *);
CB_API void cb_cmd_set_argv(cb_cmd *, const char *const *argv, size_t argc);
CB_API void cb_cmd_push_arg(cb_cmd *, const char *s);
CB_API void cb_cmd_env(cb_cmd *, const char *k, const char *v);
CB_API void cb_cmd_clear_env(cb_cmd *);
CB_API void cb_cmd_inherit_env(cb_cmd *, bool on);
CB_API void cb_cmd_cwd(cb_cmd *, const char *dir);
CB_API void cb_cmd_stdio(cb_cmd *, const char *in, const char *out, const char *err);
CB_API int cb_cmd_run(const cb_cmd *c, int *exit_code);

typedef int (*cb_cmd_handler_fn)(void);

CB_API void cb_register_cmd(const char *name, cb_cmd_handler_fn fn, const char *help);
CB_API void cb_set_default(cb_cmd_handler_fn fn, const char *help);
CB_API int cb_dispatch(cb_context *ctx);

CB_API const char *cb_workspace_root(void);
CB_API const char *cb_out_root(void);
CB_API const char *cb_tool_root(void);

static inline bool cb_is_verbose() { return cb_ctx()->args.verbose; }

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CARBIDE_H */
