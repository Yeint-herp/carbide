#include <Carbide/Recipe.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
	#define OS_WIN 1
#else
	#define OS_WIN 0
#endif
#if defined(__APPLE__)
	#define OS_MAC 1
#else
	#define OS_MAC 0
#endif
#if !OS_WIN && !OS_MAC
	#define OS_LINUX 1
#else
	#define OS_LINUX 0
#endif

static const char *env_or(const char *k, const char *defv) {
	const char *v = getenv(k);
	return (v && *v) ? v : defv;
}

static int run_simple(cb_context *ctx, const char *prog, const char *const *argv, size_t argc) {
	cb_cmd *c = cb_cmd_new();
	cb_cmd_push_arg(c, prog);
	for (size_t i = 0; i < argc; i++)
		cb_cmd_push_arg(c, argv[i]);

	if (ctx && ctx->args.verbose) {
		fprintf(stderr, "[cmd]");
		for (int i = 0; i < c->argc; i++)
			fprintf(stderr, " %s", c->argv[i]);
		fprintf(stderr, "\n");
	}
	int code = -1;
	int rc = cb_cmd_run(c, &code);
	cb_cmd_free(c);
	if (rc != 0)
		return rc;
	return code;
}

static int run_shell(cb_context *ctx, const char *cmdline) {
#if OS_WIN
	const char *argv[] = {"/C", cmdline};
	return run_simple(ctx, "cmd.exe", argv, 2);
#else
	const char *argv[] = {"-c", cmdline};
	return run_simple(ctx, "sh", argv, 2);
#endif
}

static int ensure_dir(cb_context *ctx, const char *path, int use_sudo) {
	(void)ctx;
#if OS_WIN
	(void)use_sudo;
	const char *argv[] = {path};
	return run_simple(ctx, "mkdir", argv, 1);
#else
	if (use_sudo) {
		char line[1024];
		snprintf(line, sizeof(line), "sudo install -d '%s'", path);
		return run_shell(ctx, line);
	} else {
		const char *argv[] = {"-p", path};
		return run_simple(ctx, "mkdir", argv, 2);
	}
#endif
}

static int try_prog(const char *p) {
#if OS_WIN
	(void)p;
	return 1;
#else
	char line[512];
	snprintf(line, sizeof(line), "command -v %s >/dev/null 2>&1", p);
	return run_shell(CB_NULL, line) == 0;
#endif
}

static const char *pick_cc(void) {
	const char *cc = getenv("CC");
	if (cc && *cc)
		return cc;
#if OS_WIN
	if (try_prog("cl.exe"))
		return "cl.exe";
	if (try_prog("clang.exe"))
		return "clang";
	if (try_prog("gcc.exe"))
		return "gcc";
	return "cl.exe";
#else
	if (try_prog("cc"))
		return "cc";
	if (try_prog("gcc"))
		return "gcc";
	if (try_prog("clang"))
		return "clang";
	return "cc";
#endif
}

typedef struct {
	const char *project_name;
	const char *src;
	const char *include_dir;
	const char *header;
	const char *out;
	const char *prefix;
	const char *bindir;
	const char *incdir;

	const char *cc;
	const char *cflags;
	const char *ldflags;
	const char *export_flags;
	int use_sudo;
} cfg_t;

static void load_cfg(cfg_t *c) {
	memset(c, 0, sizeof(*c));
	c->project_name = env_or("PROJECT_NAME", "carbide");
	c->src = env_or("SRC", "carbide.c");
	c->include_dir = env_or("INCLUDE_DIR", "include");
	c->header = env_or("HEADER", "include/Carbide/Recipe.h");

	static char outbuf[PATH_MAX];
	snprintf(outbuf, sizeof(outbuf), "./%s", c->project_name);
	c->out = env_or("OUT", outbuf);

	c->prefix = env_or("PREFIX", "/usr/local");

	static char bindir[PATH_MAX], incdir[PATH_MAX];
	snprintf(bindir, sizeof(bindir), "%s/bin", c->prefix);
	snprintf(incdir, sizeof(incdir), "%s/include/Carbide", c->prefix);
	c->bindir = env_or("BINDIR", bindir);
	c->incdir = env_or("INCDIR", incdir);

	c->cc = pick_cc();
	c->cflags = env_or("CFLAGS", "-O2 -g -fPIC -Wall -Wextra");
	c->ldflags = env_or("LDFLAGS", "");
	c->export_flags = env_or("EXPORT_FLAGS", "");
	c->use_sudo = getenv("CB_NO_SUDO") ? 0 : 1;

	if (c->include_dir && *c->include_dir) {
		static char cflags_ext[2048];
		snprintf(cflags_ext, sizeof(cflags_ext), "%s -I%s", c->cflags, c->include_dir);
		c->cflags = cflags_ext;
	}

	if (!*c->export_flags) {
#if OS_LINUX
		c->export_flags = "-rdynamic";
#elif OS_MAC
		c->export_flags = "-Wl,-export_dynamic";
#endif
	}
	if (!*c->ldflags) {
#if OS_LINUX
		c->ldflags = "-ldl";
#endif
	}
}

static int cmd_build() {
	cfg_t cfg;
	load_cfg(&cfg);

	cb_log_info("Building %s using %s", cfg.project_name, cfg.cc);
	cb_log_info("CFLAGS=%s", cfg.cflags);
	cb_log_info("LDFLAGS=%s", cfg.ldflags);
	cb_log_info("EXPORT_FLAGS=%s", cfg.export_flags);

	const char *ins[4];
	size_t nin = 0;
	ins[nin++] = cfg.src;
	if (cfg.header && *cfg.header)
		ins[nin++] = cfg.header;

	if (!env_or("CB_FORCE", "")[0] && !cb_needs_rebuild(cfg.out, ins, nin)) {
		cb_log_info("[skip] up-to-date: %s", cfg.out);
		return 0;
	}

	int code = 0;

#if OS_WIN
	if (strstr(cfg.cc, "cl") != CB_NULL) {
		cb_cmd *c = cb_cmd_new();
		cb_cmd_push_arg(c, cfg.cc);
		cb_cmd_push_arg(c, "/nologo");
		cb_cmd_push_arg(c, "/Zi");
		cb_cmd_push_arg(c, "/EHsc");

		char def_tool[PATH_MAX + 32];
		snprintf(def_tool, sizeof(def_tool), "/D%s%s%s", "TOOL_ROOT=\"", cfg.prefix, "\"");
		cb_cmd_push_arg(c, def_tool);

		cb_cmd_push_arg(c, cfg.src);
		{
			char outflag[PATH_MAX + 8];
			snprintf(outflag, sizeof(outflag), "/Fe:%s", cfg.out);
			cb_cmd_push_arg(c, outflag);
		}
		cb_cmd_push_arg(c, "/link");
		int rc = cb_cmd_run(c, &code);
		cb_cmd_free(c);
		if (rc != 0 || code != 0) {
			cb_log_error("compile failed (rc=%d, exit=%d)", rc, code);
			return code ? code : 1;
		}
	} else
#endif
	{
		cb_cmd *c = cb_cmd_new();
		cb_cmd_push_arg(c, cfg.cc);

		{
			char def_tool[PATH_MAX + 32];
			snprintf(def_tool, sizeof(def_tool), "-DTOOL_ROOT=\"%s\"", cfg.prefix);
			cb_cmd_push_arg(c, def_tool);
		}

		const char *f = cfg.cflags;
		char flag[512];
		size_t k = 0;
		for (size_t i = 0;; ++i) {
			char ch = f[i];
			if (ch && ch != ' ') {
				if (k + 1 < sizeof(flag))
					flag[k++] = ch;
			}
			if (!ch || ch == ' ') {
				if (k) {
					flag[k] = 0;
					cb_cmd_push_arg(c, flag);
					k = 0;
				}
				if (!ch)
					break;
			}
		}
		if (cfg.export_flags && *cfg.export_flags) {
			const char *ef = cfg.export_flags;
			k = 0;
			for (size_t i = 0;; ++i) {
				char ch = ef[i];
				if (ch && ch != ' ') {
					if (k + 1 < sizeof(flag))
						flag[k++] = ch;
				}
				if (!ch || ch == ' ') {
					if (k) {
						flag[k] = 0;
						cb_cmd_push_arg(c, flag);
						k = 0;
					}
					if (!ch)
						break;
				}
			}
		}

		cb_cmd_push_arg(c, cfg.src);
		cb_cmd_push_arg(c, "-o");
		cb_cmd_push_arg(c, cfg.out);

		if (cfg.ldflags && *cfg.ldflags) {
			const char *lf = cfg.ldflags;
			k = 0;
			for (size_t i = 0;; ++i) {
				char ch = lf[i];
				if (ch && ch != ' ') {
					if (k + 1 < sizeof(flag))
						flag[k++] = ch;
				}
				if (!ch || ch == ' ') {
					if (k) {
						flag[k] = 0;
						cb_cmd_push_arg(c, flag);
						k = 0;
					}
					if (!ch)
						break;
				}
			}
		}

		if (cb_ctx()->args.verbose) {
			fprintf(stderr, "[cmd]");
			for (int i = 0; i < c->argc; i++)
				fprintf(stderr, " %s", c->argv[i]);
			fprintf(stderr, "\n");
		}
		int rc = cb_cmd_run(c, &code);
		cb_cmd_free(c);
		if (rc != 0 || code != 0) {
			cb_log_error("compile failed (rc=%d, exit=%d)", rc, code);
			return code ? code : 1;
		}
	}

	cb_log_info("Build complete: %s", cfg.out);
	return 0;
}

static int cmd_install() {
	cfg_t cfg;
	load_cfg(&cfg);

	cb_log_info("Installing to %s", cfg.prefix);

	if (ensure_dir(cb_ctx(), cfg.bindir, cfg.use_sudo) != 0)
		return 1;
	if (ensure_dir(cb_ctx(), cfg.incdir, cfg.use_sudo) != 0)
		return 1;

#if OS_WIN
	{
		const char *args1[] = {cfg.out, cb_join(cfg.bindir, cfg.project_name)};
		if (run_simple(cb_ctx(), "copy", args1, 2) != 0) {
			cb_log_error("failed to copy binary");
			return 1;
		}
	}
	{
		const char *dest = cb_join(cfg.incdir, "Recipe.h");
		const char *args2[] = {cfg.header, dest};
		if (run_simple(cb_ctx(), "copy", args2, 2) != 0) {
			cb_log_error("failed to copy header");
			return 1;
		}
	}
#else
	{
		char line[PATH_MAX * 2];
		snprintf(line, sizeof(line), "%s install -m 0755 '%s' '%s/%s'", cfg.use_sudo ? "sudo" : "", cfg.out, cfg.bindir,
				 cfg.project_name);
		if (cfg.use_sudo)
			memmove(line, line + 5, strlen(line + 5) + 1);
		if (run_shell(cb_ctx(), cfg.use_sudo ? (snprintf(line, sizeof(line), "sudo install -m 0755 '%s' '%s/%s'",
														 cfg.out, cfg.bindir, cfg.project_name),
												line)
											 : (snprintf(line, sizeof(line), "install -m 0755 '%s' '%s/%s'", cfg.out,
														 cfg.bindir, cfg.project_name),
												line)) != 0) {
			return 1;
		}
	}
	{
		char line[PATH_MAX * 2];
		const char *dest = cb_join(cfg.incdir, "Recipe.h");
		if (run_shell(cb_ctx(),
					  cfg.use_sudo
						  ? (snprintf(line, sizeof(line), "sudo install -m 0644 '%s' '%s'", cfg.header, dest), line)
						  : (snprintf(line, sizeof(line), "install -m 0644 '%s' '%s'", cfg.header, dest), line)) != 0) {
			return 1;
		}
	}
#endif

	cb_log_info("Installed:\n  %s/%s\n  %s/Recipe.h", cfg.bindir, cfg.project_name, cfg.incdir);
	return 0;
}

static int cmd_uninstall() {
	cfg_t cfg;
	load_cfg(&cfg);

	cb_log_info("Uninstalling from %s", cfg.prefix);

#if OS_WIN
	{
		const char *args[] = {"/Q", cb_join(cfg.bindir, cfg.project_name)};
		run_simple(cb_ctx(), "del", args, 2);
	}
	{
		const char *args[] = {"/Q", cb_join(cfg.incdir, "Recipe.h")};
		run_simple(cb_ctx(), "del", args, 2);
	}
	{
		const char *args[] = {cb_join(cfg.incdir, "")};
		run_simple(cb_ctx(), "rmdir", args, 1);
	}
	{
		const char *args[] = {cb_join(cfg.bindir, "")};
		run_simple(cb_ctx(), "rmdir", args, 1);
	}
#else
	{
		char line[PATH_MAX * 2];
		snprintf(line, sizeof(line), "%s rm -f '%s/%s'", cfg.use_sudo ? "sudo" : " ", cfg.bindir, cfg.project_name);
		if (!cfg.use_sudo)
			line[0] = 'r';
		if (run_shell(cb_ctx(), line) != 0)
			cb_log_warn("skip: %s/%s not found", cfg.bindir, cfg.project_name);
	}
	{
		char line[PATH_MAX * 2];
		const char *hdr = cb_join(cfg.incdir, "Recipe.h");
		snprintf(line, sizeof(line), "%s rm -f '%s'", cfg.use_sudo ? "sudo" : " ", hdr);
		if (!cfg.use_sudo)
			line[0] = 'r';
		if (run_shell(cb_ctx(), line) != 0)
			cb_log_warn("skip: %s not found", hdr);
	}
	{
		char line[PATH_MAX * 2];
		snprintf(line, sizeof(line), "%s rmdir '%s' 2>/dev/null || true", cfg.use_sudo ? "sudo" : "", cfg.incdir);
		if (run_shell(cb_ctx(),
					  cfg.use_sudo
						  ? (snprintf(line, sizeof(line), "sudo rmdir '%s' 2>/dev/null || true", cfg.incdir), line)
						  : (snprintf(line, sizeof(line), "rmdir '%s' 2>/dev/null || true", cfg.incdir), line))) {
		}
	}
	{
		char line[PATH_MAX * 2];
		snprintf(line, sizeof(line), "%s rmdir '%s' 2>/dev/null || true", cfg.use_sudo ? "sudo" : "", cfg.bindir);
		if (run_shell(cb_ctx(),
					  cfg.use_sudo
						  ? (snprintf(line, sizeof(line), "sudo rmdir '%s' 2>/dev/null || true", cfg.bindir), line)
						  : (snprintf(line, sizeof(line), "rmdir '%s' 2>/dev/null || true", cfg.bindir), line))) {
		}
	}
#endif

	cb_log_info("Uninstall complete.");
	return 0;
}

static int cmd_help() {
	cfg_t cfg;
	load_cfg(&cfg);

	fprintf(stderr,
			"Usage:\n"
			"  carbide                Build locally into %s\n"
			"  carbide install        Install binary and header into %s\n"
			"  carbide uninstall      Remove installed binary and header from %s\n",
			cfg.out, cfg.prefix, cfg.prefix);
	return 0;
}

void carbide_recipe_main(cb_context *ctx) {
	(void)ctx;
	cb_register_cmd("build", cmd_build, "Build locally into ./<OUT>");
	cb_register_cmd("install", cmd_install, "Install binary and header into $PREFIX");
	cb_register_cmd("uninstall", cmd_uninstall, "Remove installed binary and header from $PREFIX");
	cb_register_cmd("help", cmd_help, "Show usage and env options");
	cb_set_default(cmd_build, "Build locally into ./<OUT>");
}
