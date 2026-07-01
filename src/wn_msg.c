/* wn_msg.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfNanoTLS.
 *
 * wolfNanoTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfNanoTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include "wn_msg.h"

void wn_Writer_Init(wn_Writer* w, byte* buf, word32 cap)
{
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->err = 0;
}

void wn_Write_U8(wn_Writer* w, byte v)
{
    if ((w->err == 0) && (w->len < w->cap)) {
        w->buf[w->len] = v;
        w->len++;
    }
    else {
        w->err = 1;
    }
}

void wn_Write_U16(wn_Writer* w, word16 v)
{
    if ((w->err == 0) && ((w->len + 2) <= w->cap)) {
        w->buf[w->len]     = (byte)(v >> 8);
        w->buf[w->len + 1] = (byte)(v & 0xff);
        w->len += 2;
    }
    else {
        w->err = 1;
    }
}

void wn_Write_U24(wn_Writer* w, word32 v)
{
    if ((w->err == 0) && ((w->len + 3) <= w->cap)) {
        w->buf[w->len]     = (byte)((v >> 16) & 0xff);
        w->buf[w->len + 1] = (byte)((v >> 8) & 0xff);
        w->buf[w->len + 2] = (byte)(v & 0xff);
        w->len += 3;
    }
    else {
        w->err = 1;
    }
}

void wn_Write_Bytes(wn_Writer* w, const byte* p, word32 n)
{
    if ((w->err == 0) && ((w->len + n) <= w->cap) && ((p != NULL) || (n == 0))) {
        if (n != 0) {
            XMEMCPY(w->buf + w->len, p, n);
        }
        w->len += n;
    }
    else {
        w->err = 1;
    }
}

word32 wn_Write_LenStart(wn_Writer* w, int lenBytes)
{
    word32 off;
    int i;

    for (i = 0; i < lenBytes; i++) {
        wn_Write_U8(w, 0);
    }
    off = w->len;

    return off;
}

void wn_Write_LenEnd(wn_Writer* w, word32 offset, int lenBytes)
{
    word32 contentLen;
    word32 lenPos;
    int i;

    if (w->err == 0) {
        contentLen = w->len - offset;
        lenPos = offset - (word32)lenBytes;
        for (i = 0; i < lenBytes; i++) {
            w->buf[lenPos + i] =
                (byte)((contentLen >> (8 * (lenBytes - 1 - i))) & 0xff);
        }
    }
}

void wn_Reader_Init(wn_Reader* r, const byte* buf, word32 len)
{
    r->buf = buf;
    r->len = len;
    r->pos = 0;
    r->err = 0;
}

byte wn_Read_U8(wn_Reader* r)
{
    byte v = 0;

    if ((r->err == 0) && (r->pos < r->len)) {
        v = r->buf[r->pos];
        r->pos++;
    }
    else {
        r->err = 1;
    }

    return v;
}

word16 wn_Read_U16(wn_Reader* r)
{
    word16 v = 0;

    if ((r->err == 0) && ((r->pos + 2) <= r->len)) {
        v = (word16)(((word16)r->buf[r->pos] << 8) | r->buf[r->pos + 1]);
        r->pos += 2;
    }
    else {
        r->err = 1;
    }

    return v;
}

word32 wn_Read_U24(wn_Reader* r)
{
    word32 v = 0;

    if ((r->err == 0) && ((r->pos + 3) <= r->len)) {
        v = ((word32)r->buf[r->pos] << 16) |
            ((word32)r->buf[r->pos + 1] << 8) |
            ((word32)r->buf[r->pos + 2]);
        r->pos += 3;
    }
    else {
        r->err = 1;
    }

    return v;
}

const byte* wn_Read_Bytes(wn_Reader* r, word32 n)
{
    const byte* p = NULL;

    if ((r->err == 0) && ((r->pos + n) <= r->len)) {
        p = r->buf + r->pos;
        r->pos += n;
    }
    else {
        r->err = 1;
    }

    return p;
}
