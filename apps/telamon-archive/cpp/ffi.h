// The Rust job service's C interface (src/ffi.rs). Keep the two in step.
#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {
struct TaCallOptions {
    int show_progress;
    const char *activation_token;
    const char *parent_window;
};
using TaEvent = void (*)(int kind, uint32_t id, const char *arg);

enum { TaAdded = 0, TaChanged = 1, TaFinished = 2, TaNeedsUser = 3, TaRemoved = 4 };
// The error kinds `kind` is set to.
enum { TaInvalidArgs = 1, TaTooManyJobs = 2 };

int telamon_service_start(TaEvent event);
uint32_t telamon_service_extract_here(const char *const *items, size_t n, const TaCallOptions *o, int *kind, char **msg);
uint32_t telamon_service_extract_to(const char *const *items, size_t n, const char *folder, const TaCallOptions *o, int *kind, char **msg);
uint32_t telamon_service_extract_all(const char *const *items, size_t n, const TaCallOptions *o, int *kind, char **msg);
uint32_t telamon_service_extract_entries(const char *archive, const char *const *items, size_t n, const char *folder, const TaCallOptions *o, int *kind, char **msg);
uint32_t telamon_service_compress(const char *const *items, size_t n, const char *format, const char *dest, const TaCallOptions *o, int *kind, char **msg);
uint32_t telamon_service_compress_dialog(const char *const *items, size_t n, const TaCallOptions *o, int *kind, char **msg);
uint32_t telamon_service_test(const char *const *items, size_t n, const TaCallOptions *o, int *kind, char **msg);
int telamon_service_open(const char *archive, char **path, int *kind, char **msg);
char *telamon_service_snapshot(uint32_t id);
int telamon_service_pause(uint32_t id);
int telamon_service_resume(uint32_t id);
int telamon_service_cancel(uint32_t id);
int telamon_service_answer_conflict(uint32_t id, const char *action, int all);
int telamon_service_answer_limit(uint32_t id, int go_on);
int telamon_service_answer_password(uint32_t id, const unsigned char *bytes, size_t len);
int telamon_service_confirm_extract(uint32_t id, const char *folder, char **msg);
int telamon_service_confirm_compress(uint32_t id, const char *folder, const char *name, const char *format, const char *level, char **msg);
int telamon_service_is_idle();
void telamon_service_shutdown(uint32_t ms);
void telamon_string_free(char *s);
}
