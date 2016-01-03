/*
 * Copyright (c) 2015, Christopher Zimmermann
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <zlib.h>

#define CAML_NAME_SPACE
#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/fail.h>
#include <caml/bigarray.h>
#include <caml/threads.h>


value zlib_adler32(value vadler, value vbuf)
{
  return caml_copy_int32(
      adler32(
	Int32_val(vadler),
	(Bytef *)String_val(vbuf),
	caml_string_length(vbuf)));
}

value zlib_error(z_streamp zstrm, int error)
{
  switch (error)
  {
    case Z_OK:		/* 0 */
    case Z_STREAM_END:	/* 1 */
    case Z_NEED_DICT:	/* 2 */
      return Val_int(error);
    case Z_BUF_ERROR:
      return Val_int(3);
    case Z_DATA_ERROR:
      return Val_int(4);

    case Z_VERSION_ERROR:
      caml_failwith(zstrm->msg ? zstrm->msg : "Zlib version error");
      break;
    case Z_MEM_ERROR:
      caml_raise_out_of_memory();
      break;
    case Z_STREAM_ERROR:
      caml_invalid_argument(zstrm->msg ? zstrm->msg : "Zlib stream error");
      break;
    case Z_ERRNO:
      /* strerror is not thread-safe,
       * but that's no problem since we won't context-switch here. */
      caml_failwith(strerror(errno));
      break;
    default:
      caml_failwith("Unknown return code from zlib");
      break;
  }
  /* not reached */
  assert(0);
}

#define EXTRA_MAX 4096
#define NAME_MAX 512
#define COMMENT_MAX 4096

/* structure containing the zlib gz_header together with the required buffers.
 * This simplifies allocation / freeing. */
struct wrap_header {
    gz_header zheader;
    Bytef extra[EXTRA_MAX];
    Bytef name[NAME_MAX];
    Bytef comment[COMMENT_MAX];
};

struct wrap_strm {
  z_streamp zstrm;
  struct wrap_header *header;
  int flags;
};
#define ZLIB_INFLATE 1
#define WRAP_STRM_WOSIZE \
  ((sizeof(struct wrap_strm) + sizeof(value) - 1) / sizeof(value))

static struct wrap_header* init_header()
{
  struct wrap_header *h = caml_stat_alloc(sizeof(struct wrap_header));
  h->zheader.extra = h->extra;
  h->zheader.name = h->name;
  h->zheader.comment = h->comment;
  h->zheader.extra_max = sizeof(h->extra);
  h->zheader.name_max = sizeof(h->name);
  h->zheader.comm_max = sizeof(h->comment);
  h->zheader.hcrc = 0;
  h->zheader.done = 0;
  return h;
}

void zlib_finalize(value vwrap)
{
  struct wrap_strm *wrap = Data_custom_val(vwrap);
  int ret;

  if (wrap->flags & ZLIB_INFLATE)
    ret = inflateEnd(wrap->zstrm);
  else
    ret = deflateEnd(wrap->zstrm);

  assert(ret == Z_OK || ret == Z_DATA_ERROR);
  caml_stat_free(wrap->zstrm);
  caml_stat_free(wrap->header);
}

#define ZLIB_MAX_MEMORY 1024*1024

CAMLprim value zlib_deflate_init(
    value level,
    value method,
    value windowBits,
    value memLevel,
    value strategy)
{
  value vwrap;
  struct wrap_strm *wrap;
  z_streamp zstrm;
  size_t memory;

  assert(Is_long(strategy) && Is_long(method) && 0 == Long_val(method));

  zstrm = caml_stat_alloc(sizeof(z_stream));
  memset(zstrm, 0, sizeof(z_stream));

  /* From zconf.h:
     The memory requirements for deflate are (in bytes):
	      (1 << (windowBits+2)) +  (1 << (memLevel+9))
   that is: 128K for windowBits=15  +  128K for memLevel = 8  (default values)
   plus a few kilobytes for small objects. For example, if you want to reduce
   the default memory requirements from 256K to 128K, compile with
       make CFLAGS="-O -DMAX_WBITS=14 -DMAX_MEM_LEVEL=7"
   Of course this will generally degrade compression (there's no free lunch).

     The memory requirements for inflate are (in bytes) 1 << windowBits
   that is, 32K for windowBits=15 (default value) plus a few kilobytes
   for small objects.
  */
  memory =  1 << ((abs(Int_val(windowBits)) & 15) + 2);
  memory += 1 << (Int_val(memLevel) + 9);
  vwrap = caml_alloc_final(WRAP_STRM_WOSIZE, zlib_finalize, memory, ZLIB_MAX_MEMORY);
  wrap = Data_custom_val(vwrap);
  wrap->zstrm = zstrm;
  wrap->header = NULL;
  wrap->flags = 0;

  zlib_error(zstrm,
      deflateInit2(zstrm,
	Int_val(level),
	Z_DEFLATED,
	Int_val(windowBits),
	Int_val(memLevel),
	Int_val(strategy)));

  return vwrap;
}

CAMLprim value zlib_inflate_init(value windowBits)
{
  value vwrap;
  struct wrap_strm *wrap;
  z_streamp zstrm;
  struct wrap_header *header = NULL;
  size_t memory = 0;
  const int wBits = Int_val(windowBits);

  /* prepare gz header struct for gz and automatic header detect mode */
  if (wBits > 15) {
    header = init_header();
    memory += sizeof(struct wrap_header);
  }

  memory += abs(wBits) & 15 ? 1 << (abs(wBits) & 15) : 1 << 15;
  vwrap = caml_alloc_final(WRAP_STRM_WOSIZE, zlib_finalize, memory, ZLIB_MAX_MEMORY);
  wrap = Data_custom_val(vwrap);

  wrap->flags = ZLIB_INFLATE;
  wrap->header = header;
  wrap->zstrm = zstrm = caml_stat_alloc(sizeof(z_stream));
  memset(zstrm, 0, sizeof(z_stream));

  zlib_error(zstrm, inflateInit2(zstrm, wBits));
  if (header != NULL)
    zlib_error(zstrm, inflateGetHeader(zstrm, &header->zheader));

  return vwrap;
}

CAMLprim value zlib_deflate_bound(value vwrap, value len)
{
  struct wrap_strm *wrap = Data_custom_val(vwrap);
  int ret;

  assert((wrap->flags & ZLIB_INFLATE) == 0);

  ret = deflateBound(wrap->zstrm, Long_val(len));

  if (ret < 0)
    caml_failwith("Zlib.deflate_bound");
  else
    return Val_long(ret);
}

CAMLprim value zlib_reset(value vstrm)
{
  CAMLparam1(vstrm);
  int ret;

  struct wrap_strm *wrap = Data_custom_val(Field(vstrm,0));
  z_streamp zstrm = wrap->zstrm;

  if (wrap->flags & ZLIB_INFLATE)
    ret = inflateReset(zstrm);
  else
    ret = deflateReset(zstrm);

  Field(vstrm, 3) = Val_long(0);
  Field(vstrm, 4) = Val_long(0);
  Field(vstrm, 5) = Val_long(-1);
  Field(vstrm, 6) = Val_long(-1);
  Field(vstrm, 7) = Val_long(zstrm->total_in);
  Field(vstrm, 8) = Val_long(zstrm->total_out);
  Field(vstrm, 9) = Val_long(Z_UNKNOWN);
  Store_field(vstrm,10, caml_copy_int32(zstrm->adler));
  Store_field(vstrm,10, caml_copy_int32(zstrm->adler));

  zlib_error(zstrm, ret);

  CAMLreturn(Val_unit);
}

CAMLprim value zlib_deflate_set_dictionary(value vstrm, value vdict)
{
  struct wrap_strm *wrap = Data_custom_val(vstrm);
  z_streamp zstrm = wrap->zstrm;

  assert((wrap->flags & ZLIB_INFLATE) == 0);

  zlib_error(zstrm,
      deflateSetDictionary(zstrm,
	(Bytef *)String_val(vdict),
	caml_string_length(vdict)));

  return caml_copy_int32(zstrm->adler);
}

CAMLprim value zlib_inflate_set_dictionary(value vstrm, value vdict)
{
  struct wrap_strm *wrap = Data_custom_val(vstrm);
  z_streamp zstrm = wrap->zstrm;

  assert(wrap->flags & ZLIB_INFLATE);

  return
    zlib_error(zstrm,
	inflateSetDictionary(zstrm,
	  (Bytef *)String_val(vdict),
	  caml_string_length(vdict)));
}

// Validating the header structure received by Zlib.set_header
static void validate_vheader(value vheader)
{
  /* Checking the "extra" string */
  if (Is_block(Field(vheader,4))) {
    assert(Tag_val(Field(vheader,4)) == 0);
    /* this string is _not_ expected to be zero-terminated */
    if (caml_string_length(Field(Field(vheader,4),0)) > EXTRA_MAX)
      caml_invalid_argument("Zlib.set_header: \"extra\" string is too long");
  }

  /* Checking the "name" string */
  if (Is_block(Field(vheader,5))) {
    assert(Tag_val(Field(vheader,5)) == 0);
    /* this string is expected to be zero-terminated
     * add 1 to length to copy the zero byte from ocaml string */
    if (caml_string_length(Field(Field(vheader,5),0)) + 1 > NAME_MAX)
      caml_invalid_argument("Zlib.set_header: \"name\" string is too long");
  }

  /* Checking the "comment" string */
  if (Is_block(Field(vheader,6))) {
    assert(Tag_val(Field(vheader,6)) == 0);
    /* this string is expected to be zero-terminated
     * add 1 to length to copy the zero byte from ocaml string */
    if (caml_string_length(Field(Field(vheader,6),0)) + 1 > COMMENT_MAX)
      caml_invalid_argument("Zlib.set_header: \"comment\" string is too long");
  }
}

CAMLprim value zlib_set_header(value vstrm, value vheader)
{
  struct wrap_strm *wrap = Data_custom_val(vstrm);
  z_streamp zstrm = wrap->zstrm;
  gz_headerp header;
  size_t len;

  assert((wrap->flags & ZLIB_INFLATE) == 0);
  validate_vheader(vheader);

  if (wrap->header == NULL)
    wrap->header = init_header();
  header = &wrap->header->zheader;

  memset(header, 0, sizeof(gz_header));
  header->text =  Int_val(Field(vheader,0));
  header->os   = Long_val(Field(vheader,2));
  header->time = Double_val(Field(vheader,1));

  /* extra */
  if (Is_block(Field(vheader,4))) {
    assert(Tag_val(Field(vheader,4)) == 0);
    /* this string is _not_ expected to be zero-terminated */
    len = caml_string_length(Field(Field(vheader,4),0));
    header->extra_len = len;
    memcpy(wrap->header->extra, String_val(Field(Field(vheader,4),0)), len);
  }
  else {
    assert(Int_val(Field(vheader,4)) == 0);
    header->extra = NULL;
    header->extra_len = 0;
  }

  /* name */
  if (Is_block(Field(vheader,5))) {
    assert(Tag_val(Field(vheader,5)) == 0);
    /* this string is expected to be zero-terminated
     * add 1 to length to copy the zero byte from ocaml string */
    len = caml_string_length(Field(Field(vheader,5),0)) + 1;
    memcpy(wrap->header->name, String_val(Field(Field(vheader,5),0)), len);
  }
  else {
    assert(Int_val(Field(vheader,5)) == 0);
    header->name = NULL;
  }

  /* comment */
  if (Is_block(Field(vheader,6))) {
    assert(Tag_val(Field(vheader,6)) == 0);
    /* this string is expected to be zero-terminated
     * add 1 to length to copy the zero byte from ocaml string */
    len = caml_string_length(Field(Field(vheader,6),0)) + 1;
    memcpy(wrap->header->comment, String_val(Field(Field(vheader,6),0)), len);
  }
  else {
    assert(Int_val(Field(vheader,6)) == 0);
    header->comment = NULL;
  }

  zlib_error(zstrm,
      deflateSetHeader(zstrm, header));

  return Val_unit;
}

CAMLprim value zlib_get_header(value vstrm)
{
  CAMLparam1(vstrm);
  CAMLlocal5(vheader, extra, comment, name, tmp);
  struct wrap_strm *wrap = Data_custom_val(vstrm);
  gz_headerp header = &wrap->header->zheader;
  int len;

  assert(wrap->flags & ZLIB_INFLATE);

  /* not in gzip or auto mode or zlib header found */
  if (header == NULL || header->done == -1)
    caml_raise_not_found();
  /* header not yet completed */
  if (header->done == 0)
    caml_failwith("Zlib.get_header: Header not yet completed.");
  assert(header->done == 1);

  if (header->extra != NULL) {
    tmp = caml_alloc_string(header->extra_len);
    extra = caml_alloc_small(1, 0);
    Field(extra,0) = tmp;
    memcpy(String_val(tmp), header->extra, header->extra_len);
  }
  else
    extra = Val_int(0);

  if (header->name != NULL) {
    len = strnlen((char *)header->name, header->name_max);
    tmp = caml_alloc_string(len);
    memcpy(String_val(tmp), header->name, len);
    name = caml_alloc_small(1, 0);
    Field(name,0) = tmp;
  }
  else
    name = Val_int(0);

  if (header->comment != NULL) {
    len = strnlen((char *)header->comment, header->comm_max);
    tmp = caml_alloc_string(len);
    memcpy(String_val(tmp), header->comment, len);
    comment = caml_alloc_small(1, 0);
    Field(comment,0) = tmp;
  }
  else
    comment = Val_int(0);

  tmp = caml_copy_double(header->time);

  vheader = caml_alloc_small(7, 0);
  Field(vheader,0) = Val_int(header->text);
  Field(vheader,1) = tmp;
  Field(vheader,2) = Val_int(header->os);
  Field(vheader,3) = Val_int(header->xflags);
  Field(vheader,4) = extra;
  Field(vheader,5) = name;
  Field(vheader,6) = comment;

  CAMLreturn(vheader);
}

CAMLprim value zlib_flate(value vstrm, value flush)
{
  CAMLparam2(vstrm, flush);
  int ret;
  struct wrap_strm *wrap = Data_custom_val(Field(vstrm,0));
  z_streamp zstrm = wrap->zstrm;

  assert(Is_long(flush));
  assert(Caml_ba_array_val(Field(vstrm, 1))->num_dims == 1);

# define LField(n) Long_val(Field(vstrm,(n)))

  /* By default use whole bigarray */
  zstrm->avail_in   = Caml_ba_array_val(Field(vstrm, 1))->dim[0];
  zstrm->avail_out  = Caml_ba_array_val(Field(vstrm, 2))->dim[0];
  /* if offset is given, trim length accordingly. */
  zstrm->avail_in  -= LField(3);
  zstrm->avail_out -= LField(4);
  /* given substring inside bigarray bounds? */
  if (LField(3) < 0 || LField(4) < 0 ||
      LField(5) > zstrm->avail_in || LField(6) > zstrm->avail_out)
    caml_invalid_argument("Zlib.flate");
  /* if given length is negative use default and return it. */
  if (LField(5) < 0)
    Field(vstrm,5)  = Val_long(zstrm->avail_in);
  else
    zstrm->avail_in  = LField(5);
  if (LField(6) < 0)
    Field(vstrm,6)  = Val_long(zstrm->avail_out);
  else
    zstrm->avail_out = LField(6);

  assert(zstrm->avail_in == LField(5));
  assert(zstrm->avail_out == LField(6));

  zstrm->next_in   = (Byte *)Caml_ba_data_val(Field(vstrm, 1)) + LField(3);
  zstrm->next_out  = (Byte *)Caml_ba_data_val(Field(vstrm, 2)) + LField(4);

  if (wrap->flags & ZLIB_INFLATE) {
    caml_release_runtime_system();
    ret = inflate(zstrm, Int_val(flush));
  }
  else {
    caml_release_runtime_system();
    ret = deflate(zstrm, Int_val(flush));
  }
  caml_acquire_runtime_system();

  /* Long overwriting long can be assigned directly without caml_modify */
  Field(vstrm, 3) = Val_long(LField(3) + (LField(5) - zstrm->avail_in));
  Field(vstrm, 4) = Val_long(LField(4) + (LField(6) - zstrm->avail_out));
  Field(vstrm, 5) = Val_long(zstrm->avail_in);
  Field(vstrm, 6) = Val_long(zstrm->avail_out);
  Field(vstrm, 7) = Val_long(zstrm->total_in);
  Field(vstrm, 8) = Val_long(zstrm->total_out);
  Field(vstrm, 9) = Val_long(zstrm->data_type);
  Store_field(vstrm,10, caml_copy_int32(zstrm->adler));

  CAMLreturn(zlib_error(zstrm, ret));
}
