
/*
 * callback.c - callback closure support
 * @copyright (C) 2021 SML# Development Team.
 * @author UENO Katsuhiro
 */

#include "smlsharp.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <ffi.h>
#include "splay.h"

static pthread_mutex_t callbacks_lock = PTHREAD_MUTEX_INITIALIZER;

/* A callback consists of an SML# code address, an closure environment
 * object, and a trampoline code.  Two callbacks are identical if they
 * have same SML# code address and recursively-equivalent closure
 * environment.
 */
struct callback_item {
	void *ptrs[3];  /* {trampoline, env, codeaddr} */
	int count;      /* the number of entries for the same codeaddr */
	struct callback_item *next;  /* list of callbacks of same codeaddr */
};
#define cb_trampoline ptrs[0]
#define cb_env ptrs[1]
#define cb_codeaddr ptrs[2]

static sml_tree_t *callback_closures;

static struct {
	char *base, *end;
} trampoline_heap;

/* For each trampoline, 72 bytes buffer and 16 byte alignemnt is enough for
 * any platform.  80 is the minimum multiple of 16 greater than 72. */
#define TRAMPOLINE_SIZE  80

static int
voidp_cmp(const void *x, const void *y)
{
	uintptr_t m = (uintptr_t)x, n = (uintptr_t)y;
	if (m < n) return -1;
	else if (m > n) return 1;
	else return 0;
}

static int
callback_cmp(const void *x, const void *y)
{
	const struct callback_item *item1 = x, *item2 = y;
	int ret = voidp_cmp(item1->cb_codeaddr, item2->cb_codeaddr);
	return (ret != 0) ? ret : item1->count - item2->count;
	/* NOTE: Comparing item->count by subtraction is safe since
	 * item->count is a signed integer but always positive. */
}

void
sml_callback_init()
{
	callback_closures =
		sml_tree_new(callback_cmp, sizeof(struct callback_item));
}

void
sml_callback_destroy()
{
	sml_tree_destroy(callback_closures);
	/* FIXME: we cannot release memory allocated for trampoline heap
	 * since we do not keep the address ranges of its all fragments. */
}

struct trace_fn {
	void (*fn)(void **, void *);
	void *data;
};

static void
trace_each(void *item, void *data)
{
	struct trace_fn *cls = data;
	struct callback_item *cb;
	for (cb = item; cb; cb = cb->next)
		cls->fn(&cb->cb_env, cls->data);
}

void
sml_callback_enum_ptr(void (*trace)(void **, void *), void *data)
{
	struct trace_fn cls = {trace, data};
	mutex_lock(&callbacks_lock);
	sml_tree_each(callback_closures, trace_each, &cls);
	mutex_unlock(&callbacks_lock);
}

SML_PRIMITIVE void **
sml_find_callback(void *codeaddr, void *env)
{
	struct callback_item key, *item, *found;

	mutex_lock(&callbacks_lock);

	key.cb_codeaddr = codeaddr;
	key.count = 0;
	found = sml_tree_find(callback_closures, &key);
	if (found != NULL) {
		for (;;) {
			if (sml_obj_equal(env, found->cb_env)) {
				mutex_unlock(&callbacks_lock);
				return found->ptrs;
			}
			key.count++;
			if (found->next == NULL)
				break;
			found = found->next;
		}
		item = sml_tree_insert(callback_closures, &key);
		found->next = item;
	} else {
		item = sml_tree_insert(callback_closures, &key);
	}
	item->cb_codeaddr = codeaddr;
	item->cb_trampoline = NULL;
	item->cb_env = env;
	item->next = NULL;

	mutex_unlock(&callbacks_lock);
	return item->ptrs;
}

SML_PRIMITIVE void *
sml_alloc_code()
{
	void *p;
	size_t pagesize;

	mutex_lock(&callbacks_lock);

	if (trampoline_heap.end - trampoline_heap.base < TRAMPOLINE_SIZE) {
		pagesize = getpagesize();
		p = mmap(NULL, pagesize,
			 PROT_READ | PROT_WRITE | PROT_EXEC,
			 MAP_ANON | MAP_PRIVATE,
			 -1, 0);
		if (p == MAP_FAILED)
			sml_sysfatal("mmap");
		trampoline_heap.base = p;
		trampoline_heap.end = (char*)p + pagesize;
	}

	p = trampoline_heap.base;
	trampoline_heap.base += TRAMPOLINE_SIZE;

	mutex_unlock(&callbacks_lock);
	return p;
}

static ffi_type *
char_to_type(char c)
{
	// Mimicks GHC's choice
	switch (c) {
	case 'v': return &ffi_type_void;
	case 'f': return &ffi_type_float;
	case 'd': return &ffi_type_double;
	case 'L': return &ffi_type_sint64;
	case 'l': return &ffi_type_uint64;
	case 'W': return &ffi_type_sint32;
	case 'w': return &ffi_type_uint32;
	case 'S': return &ffi_type_sint16;
	case 's': return &ffi_type_uint16;
	case 'B': return &ffi_type_sint8;
	case 'b': return &ffi_type_uint8;
	case 'p': return &ffi_type_pointer;
	default: abort();
	}
}

SML_PRIMITIVE void *
sml_create_callback(void *ml_func, void *env, int callconv, const char *types)
{
	void **ptrs = sml_find_callback((void *)ml_func, env);
	// ptrs[0]: trampoline
	if (ptrs[0] != NULL) {
		return ptrs[0];
	}
	void *exec_ptr;
	ffi_closure *closure = ffi_closure_alloc(sizeof(ffi_closure), &exec_ptr);
	if (closure == NULL) {
		sml_sysfatal("ffi_closure_alloc");
	}
	ffi_cif *cif = malloc(sizeof(ffi_cif));
	if (cif == NULL) {
		sml_sysfatal("malloc");
	}

	size_t nargs = strlen(types) - 1;
	ffi_type *result_type = char_to_type(types[0]);
	ffi_type **arg_types = malloc(sizeof(ffi_type *) * nargs);
	if (arg_types == NULL) {
		sml_sysfatal("malloc");
	}
	for (size_t i = 0; i < nargs; ++i) {
		arg_types[i] = char_to_type(types[i + 1]);
	}
	ffi_abi abi;
	switch (callconv) {
	case 0: // default
		abi = FFI_DEFAULT_ABI;
		break;
#if defined(__i386__)
	case 1: // x86 stdcall
		abi = FFI_STDCALL;
		break;
#endif
	case 2: // fastcc
		sml_sysfatal("fastcc not supported");
	default:
		sml_sysfatal("unsupported calling convention");
	}
	if (ffi_prep_cif(cif, abi, nargs, result_type, arg_types) != FFI_OK) {
		sml_sysfatal("ffi_prep_cif");
	}
	if (ffi_prep_closure_loc(closure, cif, (void (*)(ffi_cif *, void *, void **, void *))ml_func, env, exec_ptr) != FFI_OK) {
		sml_sysfatal("ffi_prep_closure_loc");
	}
	ptrs[0] = exec_ptr;
	return exec_ptr;
}
