/*----------------------------------------------------------------------------+
 |                                                                            |
 |   Package: krypto                                                          |
 |   Author: Eugene Jhong                                                     |
 |                                                                            |
 +----------------------------------------------------------------------------*/

/*
 * Copyright (c) 1997 Stanford University
 *
 * Permission to use, copy, modify, distribute, and sell this software and
 * its documentation for any purpose is hereby granted without fee, provided
 * that the above copyright notices and this permission notice appear in
 * all copies of the software and related documentation.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL STANFORD BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include "krypto.h"
/*#include "krypto_locl.h"*/

#define NUM_TESTS 34
static unsigned char ecb_data[NUM_TESTS][8]={
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
        {0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11},
        {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF},
        {0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10},
        {0x7C,0xA1,0x10,0x45,0x4A,0x1A,0x6E,0x57},
        {0x01,0x31,0xD9,0x61,0x9D,0xC1,0x37,0x6E},
        {0x07,0xA1,0x13,0x3E,0x4A,0x0B,0x26,0x86},
        {0x38,0x49,0x67,0x4C,0x26,0x02,0x31,0x9E},
        {0x04,0xB9,0x15,0xBA,0x43,0xFE,0xB5,0xB6},
        {0x01,0x13,0xB9,0x70,0xFD,0x34,0xF2,0xCE},
        {0x01,0x70,0xF1,0x75,0x46,0x8F,0xB5,0xE6},
        {0x43,0x29,0x7F,0xAD,0x38,0xE3,0x73,0xFE},
        {0x07,0xA7,0x13,0x70,0x45,0xDA,0x2A,0x16},
        {0x04,0x68,0x91,0x04,0xC2,0xFD,0x3B,0x2F},
        {0x37,0xD0,0x6B,0xB5,0x16,0xCB,0x75,0x46},
        {0x1F,0x08,0x26,0x0D,0x1A,0xC2,0x46,0x5E},
        {0x58,0x40,0x23,0x64,0x1A,0xBA,0x61,0x76},
        {0x02,0x58,0x16,0x16,0x46,0x29,0xB0,0x07},
        {0x49,0x79,0x3E,0xBC,0x79,0xB3,0x25,0x8F},
        {0x4F,0xB0,0x5E,0x15,0x15,0xAB,0x73,0xA7},
        {0x49,0xE9,0x5D,0x6D,0x4C,0xA2,0x29,0xBF},
        {0x01,0x83,0x10,0xDC,0x40,0x9B,0x26,0xD6},
        {0x1C,0x58,0x7F,0x1C,0x13,0x92,0x4F,0xEF},
        {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01},
        {0x1F,0x1F,0x1F,0x1F,0x0E,0x0E,0x0E,0x0E},
        {0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1,0xFE},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
        {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF},
        {0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10}};

static unsigned char plain_data[NUM_TESTS][8]={
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
        {0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x01},
        {0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11},
        {0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11},
        {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF},
        {0x01,0xA1,0xD6,0xD0,0x39,0x77,0x67,0x42},
        {0x5C,0xD5,0x4C,0xA8,0x3D,0xEF,0x57,0xDA},
        {0x02,0x48,0xD4,0x38,0x06,0xF6,0x71,0x72},
        {0x51,0x45,0x4B,0x58,0x2D,0xDF,0x44,0x0A},
        {0x42,0xFD,0x44,0x30,0x59,0x57,0x7F,0xA2},
        {0x05,0x9B,0x5E,0x08,0x51,0xCF,0x14,0x3A},
        {0x07,0x56,0xD8,0xE0,0x77,0x47,0x61,0xD2},
        {0x76,0x25,0x14,0xB8,0x29,0xBF,0x48,0x6A},
        {0x3B,0xDD,0x11,0x90,0x49,0x37,0x28,0x02},
        {0x26,0x95,0x5F,0x68,0x35,0xAF,0x60,0x9A},
        {0x16,0x4D,0x5E,0x40,0x4F,0x27,0x52,0x32},
        {0x6B,0x05,0x6E,0x18,0x75,0x9F,0x5C,0xCA},
        {0x00,0x4B,0xD6,0xEF,0x09,0x17,0x60,0x62},
        {0x48,0x0D,0x39,0x00,0x6E,0xE7,0x62,0xF2},
        {0x43,0x75,0x40,0xC8,0x69,0x8F,0x3C,0xFA},
        {0x07,0x2D,0x43,0xA0,0x77,0x07,0x52,0x92},
        {0x02,0xFE,0x55,0x77,0x81,0x17,0xF1,0x2A},
        {0x1D,0x9D,0x5C,0x50,0x18,0xF7,0x28,0xC2},
        {0x30,0x55,0x32,0x28,0x6D,0x6F,0x29,0x5A},
        {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF},
        {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF},
        {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF},
        {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}};

static unsigned char bf_data[NUM_TESTS][8]={
        {0x4E,0xF9,0x97,0x45,0x61,0x98,0xDD,0x78},
        {0x51,0x86,0x6F,0xD5,0xB8,0x5E,0xCB,0x8A},
        {0x7D,0x85,0x6F,0x9A,0x61,0x30,0x63,0xF2},
        {0x24,0x66,0xDD,0x87,0x8B,0x96,0x3C,0x9D},
        {0x61,0xF9,0xC3,0x80,0x22,0x81,0xB0,0x96},
        {0x7D,0x0C,0xC6,0x30,0xAF,0xDA,0x1E,0xC7},
        {0x4E,0xF9,0x97,0x45,0x61,0x98,0xDD,0x78},
        {0x0A,0xCE,0xAB,0x0F,0xC6,0xA0,0xA2,0x8D},
        {0x59,0xC6,0x82,0x45,0xEB,0x05,0x28,0x2B},
        {0xB1,0xB8,0xCC,0x0B,0x25,0x0F,0x09,0xA0},
        {0x17,0x30,0xE5,0x77,0x8B,0xEA,0x1D,0xA4},
        {0xA2,0x5E,0x78,0x56,0xCF,0x26,0x51,0xEB},
        {0x35,0x38,0x82,0xB1,0x09,0xCE,0x8F,0x1A},
        {0x48,0xF4,0xD0,0x88,0x4C,0x37,0x99,0x18},
        {0x43,0x21,0x93,0xB7,0x89,0x51,0xFC,0x98},
        {0x13,0xF0,0x41,0x54,0xD6,0x9D,0x1A,0xE5},
        {0x2E,0xED,0xDA,0x93,0xFF,0xD3,0x9C,0x79},
        {0xD8,0x87,0xE0,0x39,0x3C,0x2D,0xA6,0xE3},
        {0x5F,0x99,0xD0,0x4F,0x5B,0x16,0x39,0x69},
        {0x4A,0x05,0x7A,0x3B,0x24,0xD3,0x97,0x7B},
        {0x45,0x20,0x31,0xC1,0xE4,0xFA,0xDA,0x8E},
        {0x75,0x55,0xAE,0x39,0xF5,0x9B,0x87,0xBD},
        {0x53,0xC5,0x5F,0x9C,0xB4,0x9F,0xC0,0x19},
        {0x7A,0x8E,0x7B,0xFA,0x93,0x7E,0x89,0xA3},
        {0xCF,0x9C,0x5D,0x7A,0x49,0x86,0xAD,0xB5},
        {0xD1,0xAB,0xB2,0x90,0x65,0x8B,0xC7,0x78},
        {0x55,0xCB,0x37,0x74,0xD1,0x3E,0xF2,0x01},
        {0xFA,0x34,0xEC,0x48,0x47,0xB2,0x68,0xB2},
        {0xA7,0x90,0x79,0x51,0x08,0xEA,0x3C,0xAE},
        {0xC3,0x9E,0x07,0x2D,0x9F,0xAC,0x63,0x1D},
        {0x01,0x49,0x33,0xE0,0xCD,0xAF,0xF6,0xE4},
        {0xF2,0x1E,0x9A,0x77,0xB7,0x1C,0x49,0xBC},
        {0x24,0x59,0x46,0x88,0x57,0x54,0x36,0x9A},
        {0x6B,0x5C,0x5A,0x9C,0x5D,0x9E,0x0A,0x5A},
        };

static unsigned char des_data[NUM_TESTS][8]={
        {0x8C,0xA6,0x4D,0xE9,0xC1,0xB1,0x23,0xA7},
        {0x73,0x59,0xB2,0x16,0x3E,0x4E,0xDC,0x58},
        {0x95,0x8E,0x6E,0x62,0x7A,0x05,0x55,0x7B},
        {0xF4,0x03,0x79,0xAB,0x9E,0x0E,0xC5,0x33},
        {0x17,0x66,0x8D,0xFC,0x72,0x92,0x53,0x2D},
        {0x8A,0x5A,0xE1,0xF8,0x1A,0xB8,0xF2,0xDD},
        {0x8C,0xA6,0x4D,0xE9,0xC1,0xB1,0x23,0xA7},
        {0xED,0x39,0xD9,0x50,0xFA,0x74,0xBC,0xC4},
        {0x69,0x0F,0x5B,0x0D,0x9A,0x26,0x93,0x9B},
        {0x7A,0x38,0x9D,0x10,0x35,0x4B,0xD2,0x71},
        {0x86,0x8E,0xBB,0x51,0xCA,0xB4,0x59,0x9A},
        {0x71,0x78,0x87,0x6E,0x01,0xF1,0x9B,0x2A},
        {0xAF,0x37,0xFB,0x42,0x1F,0x8C,0x40,0x95},
        {0x86,0xA5,0x60,0xF1,0x0E,0xC6,0xD8,0x5B},
        {0x0C,0xD3,0xDA,0x02,0x00,0x21,0xDC,0x09},
        {0xEA,0x67,0x6B,0x2C,0xB7,0xDB,0x2B,0x7A},
        {0xDF,0xD6,0x4A,0x81,0x5C,0xAF,0x1A,0x0F},
        {0x5C,0x51,0x3C,0x9C,0x48,0x86,0xC0,0x88},
        {0x0A,0x2A,0xEE,0xAE,0x3F,0xF4,0xAB,0x77},
        {0xEF,0x1B,0xF0,0x3E,0x5D,0xFA,0x57,0x5A},
        {0x88,0xBF,0x0D,0xB6,0xD7,0x0D,0xEE,0x56},
        {0xA1,0xF9,0x91,0x55,0x41,0x02,0x0B,0x56},
        {0x6F,0xBF,0x1C,0xAF,0xCF,0xFD,0x05,0x56},
        {0x2F,0x22,0xE4,0x9B,0xAB,0x7C,0xA1,0xAC},
        {0x5A,0x6B,0x61,0x2C,0xC2,0x6C,0xCE,0x4A},
        {0x5F,0x4C,0x03,0x8E,0xD1,0x2B,0x2E,0x41},
        {0x63,0xFA,0xC0,0xD0,0x34,0xD9,0xF7,0x93},
        {0x61,0x7B,0x3A,0x0C,0xE8,0xF0,0x71,0x00},
        {0xDB,0x95,0x86,0x05,0xF8,0xC8,0xC6,0x06},
        {0xED,0xBF,0xD1,0xC6,0x6C,0x29,0xCC,0xC7},
        {0x35,0x55,0x50,0xB2,0x15,0x0E,0x24,0x51},
        {0xCA,0xAA,0xAF,0x4D,0xEA,0xF1,0xDB,0xAE},
        {0xD5,0xD4,0x4F,0xF7,0x20,0x68,0x3D,0x0D},
        {0x2A,0x2B,0xB0,0x08,0xDF,0x97,0xC2,0xF2}};

static unsigned char des3_data[NUM_TESTS-1][8]={
        {0x92,0x95,0xB5,0x9B,0xB3,0x84,0x73,0x6E},
        {0x19,0x9E,0x9D,0x6D,0xF3,0x9A,0xA8,0x16},
        {0x2A,0x4B,0x4D,0x24,0x52,0x43,0x84,0x27},
        {0x35,0x84,0x3C,0x01,0x9D,0x18,0xC5,0xB6},
        {0x4A,0x5B,0x2F,0x42,0xAA,0x77,0x19,0x25},
        {0xA0,0x6B,0xA9,0xB8,0xCA,0x5B,0x17,0x8A},
        {0xAB,0x9D,0xB7,0xFB,0xED,0x95,0xF2,0x74},
        {0x3D,0x25,0x6C,0x23,0xA7,0x25,0x2F,0xD6},
        {0xB7,0x6F,0xAB,0x4F,0xBD,0xBD,0xB7,0x67},
        {0x8F,0x68,0x27,0xD6,0x9C,0xF4,0x1A,0x10},
        {0x82,0x57,0xA1,0xD6,0x50,0x5E,0x81,0x85},
        {0xA2,0x0F,0x0A,0xCD,0x80,0x89,0x7D,0xFA},
        {0xCD,0x2A,0x53,0x3A,0xDB,0x0D,0x7E,0xF3},
        {0xD2,0xC2,0xBE,0x27,0xE8,0x1B,0x68,0xE3},
        {0xE9,0x24,0xCF,0x4F,0x89,0x3C,0x5B,0x0A},
        {0xA7,0x18,0xC3,0x9F,0xFA,0x9F,0xD7,0x69},
        {0x77,0x2C,0x79,0xB1,0xD2,0x31,0x7E,0xB1},
        {0x49,0xAB,0x92,0x7F,0xD0,0x22,0x00,0xB7},
        {0xCE,0x1C,0x6C,0x7D,0x85,0xE3,0x4A,0x6F},
        {0xBE,0x91,0xD6,0xE1,0x27,0xB2,0xE9,0x87},
        {0x70,0x28,0xAE,0x8F,0xD1,0xF5,0x74,0x1A},
        {0xAA,0x37,0x80,0xBB,0xF3,0x22,0x1D,0xDE},
        {0xA6,0xC4,0xD2,0x5E,0x28,0x93,0xAC,0xB3},
        {0x22,0x07,0x81,0x5A,0xE4,0xB7,0x1A,0xAD},
        {0xDC,0xCE,0x05,0xE7,0x07,0xBD,0xF5,0x84},
        {0x26,0x1D,0x39,0x2C,0xB3,0xBA,0xA5,0x85},
        {0xB4,0xF7,0x0F,0x72,0xFB,0x04,0xF0,0xDC},
        {0x95,0xBA,0xA9,0x4E,0x87,0x36,0xF2,0x89},
        {0xD4,0x07,0x3A,0xF1,0x5A,0x17,0x82,0x0E},
        {0xEF,0x6F,0xAF,0xA7,0x66,0x1A,0x7E,0x89},
        {0xC1,0x97,0xF5,0x58,0x74,0x8A,0x20,0xE7},
        {0x43,0x34,0xCF,0xDA,0x22,0xC4,0x86,0xC8},
        {0x08,0xD7,0xB4,0xFB,0x62,0x9D,0x08,0x85}};

static unsigned char idea_data[NUM_TESTS-1][8]={
        {0x90,0x9f,0x54,0xcd,0x33,0xee,0x89,0xda},
        {0x98,0x1d,0x6e,0x73,0x5f,0x04,0x65,0xc1},
        {0x3e,0xce,0x1f,0x80,0x2b,0x72,0x01,0xf8},
        {0xa7,0x6c,0x64,0x7f,0x24,0xe5,0xa0,0x4a},
        {0x89,0x7a,0xe8,0x35,0x13,0x18,0x66,0x10},
        {0x82,0x68,0xc3,0x84,0xca,0x8d,0x0e,0x96},
        {0x20,0x6d,0xef,0xb6,0xde,0x17,0x26,0x38},
        {0x7b,0x1c,0xc1,0xe4,0x21,0x24,0x0f,0x3d},
        {0xad,0xea,0x94,0xae,0x24,0x18,0xaf,0x25},
        {0x00,0xdd,0x60,0xd3,0x8f,0x4a,0x94,0xf7},
        {0x73,0x99,0xe2,0x95,0x98,0xaf,0xf1,0x3b},
        {0xa2,0xbf,0xbc,0xe5,0x13,0x63,0x67,0xa7},
        {0xa8,0xc0,0x15,0xcf,0x09,0x6b,0x02,0x02},
        {0x7c,0x01,0x29,0x64,0xc5,0x61,0x6b,0xea},
        {0x8b,0x24,0x58,0x7d,0xf7,0x30,0x2a,0xb5},
        {0x66,0xb3,0x09,0x6c,0xa5,0x98,0xa0,0xac},
        {0x55,0xe7,0x09,0xd9,0x43,0xdb,0x64,0x87},
        {0x79,0xca,0x42,0xd3,0x52,0x08,0xe5,0x6e},
        {0xc3,0x76,0x8a,0x9b,0x1b,0x79,0xd3,0x02},
        {0xab,0xad,0x7c,0x03,0xab,0xc6,0xd4,0xd5},
        {0x7f,0x9c,0xeb,0xf0,0x24,0x50,0x41,0x0d},
        {0xa4,0xab,0x0b,0x7f,0x58,0x9e,0x2f,0x7e},
        {0x89,0x3d,0x26,0x02,0x0e,0xa7,0xfd,0x93},
        {0x11,0xd9,0xe2,0xdb,0x5a,0x9d,0x98,0xc4},
        {0x41,0x78,0xf0,0x43,0xbd,0x33,0xcf,0x36},
        {0x5a,0xf1,0x4e,0xd0,0xd5,0x97,0x5b,0x6d},
        {0xea,0xcc,0x78,0x3a,0xea,0xfb,0x5a,0xd9},
        {0xd8,0x0f,0x37,0x5a,0xa8,0x3f,0xe2,0x15},
        {0xd2,0x35,0xb1,0xff,0x3a,0x29,0x44,0x0b},
        {0xff,0x6f,0xbd,0x5a,0xf0,0xa8,0xdd,0x02},
        {0x27,0xa0,0xa8,0xbb,0x95,0xa8,0x1e,0x2c},
        {0x66,0x11,0x84,0xa5,0x80,0xf0,0x65,0xe0},
        {0xc7,0x70,0x68,0x07,0xd3,0x59,0xa9,0x60}};

static unsigned char test_key [24] =
  { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };

static unsigned char test_iv [8] =
  { 0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };

static char test_data[40] = 
  "7654321 Now is the time for ";

static unsigned char bf_cbc_ok[32] =
  { 0x6B,0x77,0xB4,0xD6,0x30,0x06,0xDE,0xE6,
    0x05,0xB1,0x56,0xE2,0x74,0x03,0x97,0x93,
    0x58,0xDE,0xB9,0xE7,0x15,0x46,0x16,0xD9,
    0x59,0xF1,0x65,0x2B,0xD5,0xFF,0x92,0xCC };

static unsigned char bf_cfb64_ok[] =
  { 0xE7,0x32,0x14,0xA2,0x82,0x21,0x39,0xCA,
    0xF2,0x6E,0xCF,0x6D,0x2E,0xB9,0xE7,0x6E,
    0x3D,0xA3,0xDE,0x04,0xD1,0x51,0x72,0x00,
    0x51,0x9D,0x57,0xA6,0xC3 };

static unsigned char bf_ofb64_ok[] = 
  { 0xE7,0x32,0x14,0xA2,0x82,0x21,0x39,0xCA,
    0x62,0xB3,0x43,0xCC,0x5B,0x65,0x58,0x73,
    0x10,0xDD,0x90,0x8D,0x0C,0x24,0x1B,0x22,
    0x63,0xC2,0xCF,0x80,0xDA };

static unsigned char des_cbc_ok[] =
  { 0xcc,0xd1,0x73,0xff,0xab,0x20,0x39,0xf4,
    0xac,0xd8,0xae,0xfd,0xdf,0xd8,0xa1,0xeb,
    0x46,0x8e,0x91,0x15,0x78,0x88,0xba,0x68,
    0x1d,0x26,0x93,0x97,0xf7,0xfe,0x62,0xb4 };

static unsigned char des3_cbc_ok[] =
  { 0x3F,0xE3,0x01,0xC9,0x62,0xAC,0x01,0xD0,
    0x22,0x13,0x76,0x3C,0x1C,0xBD,0x4C,0xDC,
    0x79,0x96,0x57,0xC0,0x64,0xEC,0xF5,0xD4,
    0x1C,0x67,0x38,0x12,0xCF,0xDE,0x96,0x75 };

static unsigned char des_cfb_key[24]=
  { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef };
static unsigned char des_cfb_iv[8]={0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef};
static unsigned char des_plain[24]=
        {
        0x4e,0x6f,0x77,0x20,0x69,0x73,
        0x20,0x74,0x68,0x65,0x20,0x74,
        0x69,0x6d,0x65,0x20,0x66,0x6f,
        0x72,0x20,0x61,0x6c,0x6c,0x20
        };
static unsigned char des_cfb_cipher64[24]={
        0xF3,0x09,0x62,0x49,0xC7,0xF4, 0x6E,0x51,0xA6,0x9E,0x83,0x9B,
        0x1A,0x92,0xF7,0x84,0x03,0x46, 0x71,0x33,0x89,0x8E,0xA6,0x22 };

static unsigned char des_ofb_key[24]=
  { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef };
static unsigned char des_ofb_iv[8]={0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef};
static unsigned char des_ofb_cipherer[24]=
        {
        0xf3,0x09,0x62,0x49,0xc7,0xf4,0x6e,0x51,
        0x35,0xf2,0x4a,0x24,0x2e,0xeb,0x3d,0x3f,
        0x3d,0x6d,0x5b,0xe3,0x25,0x5a,0xf8,0xc3
        };

static unsigned char cast_key[] = {
  0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
  0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A
};

static unsigned char cast_plain[] =
{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

static unsigned char cast_cipher128[] =
{ 0x23, 0x8B, 0x4F, 0xE5, 0x84, 0x7E, 0x44, 0xB2 };

static unsigned char cast_cipher80[] =
{ 0xEB, 0x6A, 0x71, 0x1A, 0x2C, 0x02, 0x27, 0x1B };

static unsigned char cast_cipher40[] =
{ 0x7A, 0xC8, 0x16, 0xD1, 0x6E, 0x9B, 0x30, 0x2E };

static unsigned char cast_avec[] = {
  0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
  0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A
};

static unsigned char cast_bvec[] = {
  0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
  0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A
};

static unsigned char cast_aver[] = {
  0xEE, 0xA9, 0xD0, 0xA2, 0x49, 0xFD, 0x3B, 0xA6,
  0xB3, 0x43, 0x6F, 0xB8, 0x9D, 0x6D, 0xCA, 0x92
};

static unsigned char cast_bver[] = {
  0xB2, 0xC9, 0x5E, 0xB0, 0x0C, 0x31, 0xAD, 0x71,
  0x80, 0xAC, 0x05, 0xB8, 0xE8, 0x3D, 0x69, 0x6E
};

void
print64(s)
     unsigned char * s;
{
  int i;

  for(i = 0; i < 8; ++i)
    printf(" %02x", s[i]);
}


int
main(argc, argv)
  int argc;
  char **argv;
{
  cipher_desc * desc;
  cipher * ciph;
  unsigned char in[40];
  unsigned char out[40];
  unsigned long len;
  unsigned char *list = cipher_getlist ();
  int i;
  int status = 0;

  /* print out supported ciphers */

  printf ("\nSupported Ciphers:\n\n");
  for (i = 0; i < strlen (list); i++)
  {
    desc = cipher_getdescbyid (list[i]);
    printf ("  %s (%d)\n", desc->name, desc->id);
  }
  printf ("\n");

  /* BLOWFISH_ECB */

  printf ("Testing BLOWFISH_ECB...\n");
  memset (in, 0, 40); memset (out, 0, 40);
  desc = cipher_getdescbyname ("BLOWFISH_ECB");

  if (desc)
  {
    ciph = cipher_new (desc);

    for (i = 0; i < NUM_TESTS; i++)
    {
      cipher_initencrypt (ciph, ecb_data[i], 8);
      cipher_crypt (ciph, &(plain_data[i][0]),out,8);
      if (memcmp (out, &(bf_data[i][0]), 8) != 0)
        { printf ("BLOWFISH_ECB encrypt error\n"); status = 1; }

      cipher_initdecrypt (ciph, ecb_data[i], 8);
      cipher_crypt (ciph, out, out, 8);
      if (memcmp (out, &(plain_data[i][0]), 8) != 0)
        { printf ("BLOWFISH_ECB decrypt error\n"); status = 1; }
    }

    cipher_delete (ciph);
  }

  len = strlen (test_data) + 1;

  /* BLOWFISH_CBC */

  printf ("Testing BLOWFISH_CBC...\n");
  memset (in, 0, 40); memset (out, 0, 40);
  desc = cipher_getdescbyname ("BLOWFISH_CBC");

  if (desc)
  {
    ciph = cipher_new (desc);

    cipher_initencrypt (ciph, test_key, 16);
    cipher_setiv (ciph, test_iv, 8);
    cipher_crypt (ciph, test_data, out, len);
    if (memcmp (out, bf_cbc_ok, 32) != 0)
      { printf ("BLOWFISH_CBC encrypt error\n"); status = 1; }

    cipher_initdecrypt (ciph, test_key, 16);
    cipher_setiv (ciph, test_iv, 8);
    cipher_crypt (ciph, out, in, len);
    if (memcmp (in, test_data, 32) != 0)
    { printf ("BLOWFISH_CBC decrypt error\n"); status = 1; }

    cipher_delete (ciph);
  }

  /* BLOWFISH_CFB64 */

  printf ("Testing BLOWFISH_CFB64...\n");
  memset (in, 0, 40); memset (out, 0, 40);
  desc = cipher_getdescbyname ("BLOWFISH_CFB64");

  if (desc)
  {
    ciph = cipher_new (desc);

    cipher_initencrypt (ciph, test_key, 16);
    cipher_setiv (ciph, test_iv, 8);
    cipher_crypt (ciph, test_data, out, len);
    if (memcmp (out, bf_cfb64_ok, len) != 0)
      { printf ("BLOWFISH_CFB64 encrypt error\n"); status = 1; }
  
    cipher_initdecrypt (ciph, test_key, 16);
    cipher_setiv (ciph, test_iv, 8);
    cipher_crypt (ciph, out, in, len);
    if (memcmp (in, test_data, len) != 0)
      { printf ("BLOWFISH_CFB64 decrypt error\n"); status = 1; }

    cipher_delete (ciph);
  }

  /* BLOWFISH_OFB64 */

  printf ("Testing BLOWFISH_OFB64...\n");
  memset (in, 0, 40); memset (out, 0, 40);
  desc = cipher_getdescbyname ("BLOWFISH_OFB64");

  if (desc)
  {
    ciph = cipher_new (desc);

    cipher_initencrypt (ciph, test_key, 16);
    cipher_setiv (ciph, test_iv, 8);
    cipher_crypt (ciph, test_data, out, len);
    if (memcmp (out, bf_ofb64_ok, len) != 0)
      { printf ("BLOWFISH_OFB64 encrypt error\n"); status = 1; }
  
    cipher_initdecrypt (ciph, test_key, 16);
    cipher_setiv (ciph, test_iv, 8);
    cipher_crypt (ciph, out, in, len);
    if (memcmp (in, test_data, len) != 0)
      { printf ("BLOWFISH_OFB64 decrypt error\n"); status = 1; }
  
    cipher_delete (ciph);
  }

  /* DES_ECB */

  printf ("Testing DES_ECB...\n");
  memset (in, 0, 40); memset (out, 0, 40);
  desc = cipher_getdescbyname ("DES_ECB");

  if (desc)
  {
    ciph = cipher_new (desc);

    for (i = 0; i < NUM_TESTS; i++)
    {
      unsigned char key[8];
      memcpy (key, ecb_data[i], 8);

      cipher_initencrypt (ciph, key, 8);
      cipher_crypt (ciph, &(plain_data[i][0]),out,8);
      if (memcmp (out, &(des_data[i][0]), 8) != 0)
        { printf ("DES_ECB encrypt error\n"); status = 1; }

      cipher_initdecrypt (ciph, key, 8);
      cipher_crypt (ciph, out, out, 8);
      if (memcmp (out, &(plain_data[i][0]), 8) != 0)
        { printf ("DES_ECB decrypt error\n"); status = 1; }
    }

    cipher_delete (ciph);
  }

  /* DES_CBC */

  printf ("Testing DES_CBC...\n");
  memset (in, 0, 40); memset (out, 0, 40);
  desc = cipher_getdescbyname ("DES_CBC");

  if (desc)
  {
    ciph = cipher_new (desc);

    cipher_initencrypt (ciph, test_key, 8);
    cipher_setiv (ciph, test_iv, 8);
    cipher_crypt (ciph, test_data, out, len);
    if (memcmp (out, des_cbc_ok, 32) != 0)
      { printf ("DES_CBC encrypt error\n"); status = 1; }
  
    cipher_initdecrypt (ciph, test_key, 8);
    cipher_setiv (ciph, test_iv, 8);
    cipher_crypt (ciph, out, in, len);
    if (memcmp (in, test_data, 32) != 0)
      { printf ("DES_CBC decrypt error\n"); status = 1; }

    cipher_delete (ciph);
  }

  /* DES_CFB64 */

  printf ("Testing DES_CFB64...\n");
  memset (in, 0, 40); memset (out, 0, 40);
  desc = cipher_getdescbyname ("DES_CFB64");

  if (desc)
  {
    ciph = cipher_new (desc);

    cipher_initencrypt (ciph, des_cfb_key, 8);
    cipher_setiv (ciph, des_cfb_iv, 8);
    cipher_crypt (ciph, des_plain, out, 12);
    cipher_crypt (ciph, &(des_plain[12]), &(out[12]), 12);
    if (memcmp (out, des_cfb_cipher64, 24) != 0)
      { printf ("DES_CFB64 encrypt error\n"); status = 1; }

    cipher_initdecrypt (ciph, des_cfb_key, 8);
    cipher_setiv (ciph, des_cfb_iv, 8);
    cipher_crypt (ciph, out, in, 17);
    cipher_crypt (ciph, &(out[17]), &(in[17]), 7);
    if (memcmp (in, des_plain, 24) != 0)
      { printf ("DES_CFB64 decrypt error\n"); status = 1; }

    cipher_delete (ciph);
  }

  /* DES_OFB64 */

  printf ("Testing DES_OFB64...\n");
  memset (in, 0, 40); memset (out, 0, 40);
  desc = cipher_getdescbyname ("DES_OFB64");

  if (desc)
  {
    ciph = cipher_new (desc);

    cipher_initencrypt (ciph, des_ofb_key, 8);
    cipher_setiv (ciph, des_ofb_iv, 8);
    for (i = 0; i < sizeof (des_plain); i++)
      cipher_crypt (ciph, &(des_plain[i]), &(out[i]), 1);
    if (memcmp (out, des_ofb_cipherer, 24) != 0)
      { printf ("DES_OFB64 encrypt error\n"); status = 1; }
  
    cipher_initdecrypt (ciph, des_ofb_key, 8);
    cipher_setiv (ciph, des_ofb_iv, 8);
    cipher_crypt (ciph, out, in, 24);
    if (memcmp (in, des_plain, 24) != 0)
      { printf ("DES_OFB64 decrypt error\n"); status = 1; }
  
    cipher_delete (ciph);
  }

  /* DES3_ECB */

  printf ("Testing DES3_ECB...\n");
  memset (in, 0, 40); memset (out, 0, 40);
  desc = cipher_getdescbyname ("DES3_ECB");

  if (desc)
  {
    ciph = cipher_new (desc);

    for (i = 0; i < NUM_TESTS-1; i++)
    {
      unsigned char key[24];
  
      memcpy (key, ecb_data[i], 8);
      memcpy (key+8, ecb_data[i+1], 8);
  
      cipher_initencrypt (ciph, key, 16);
      cipher_crypt (ciph, &(plain_data[i][0]),out,8);
      if (memcmp (out, &(des3_data[i][0]), 8) != 0)
        { printf ("DES3_ECB encrypt error\n"); status = 1; }
  
      cipher_initdecrypt (ciph, key, 16);
      cipher_crypt (ciph, out, out, 8);
      if (memcmp (out, &(plain_data[i][0]), 8) != 0)
        { printf ("DES3_ECB decrypt error\n"); status = 1; }
    }
  
    cipher_delete (ciph);
  }

  /* DES3_CBC */

  printf ("Testing DES3_CBC...\n");
  memset (in, 0, 40); memset (out, 0, 40);
  desc = cipher_getdescbyname ("DES3_CBC");

  if (desc)
  {
    ciph = cipher_new (desc);

    cipher_initencrypt (ciph, test_key, 24);
    cipher_setiv (ciph, test_iv, 8);
    cipher_crypt (ciph, test_data, out, len);
    if (memcmp (out, des3_cbc_ok, 32) != 0)
      { printf ("DES3_CBC encrypt error\n"); status = 1; }
  
    cipher_initdecrypt (ciph, test_key, 24);
    cipher_setiv (ciph, test_iv, 8);
    cipher_crypt (ciph, out, in, len);
    if (memcmp (in, test_data, 32) != 0)
      { printf ("DES3_CBC decrypt error\n"); status = 1; }
  
    cipher_delete (ciph);
  }

  /* DES3_CFB64 */

  printf ("Testing DES3_CFB64...\n");
  memset (in, 0, 40); memset (out, 0, 40);
  desc = cipher_getdescbyname ("DES3_CFB64");

  if (desc)
  {
    ciph = cipher_new (desc);

    cipher_initencrypt (ciph, des_cfb_key, 24);
    cipher_setiv (ciph, des_cfb_iv, 8);
    cipher_crypt (ciph, des_plain, out, 12);
    cipher_crypt (ciph, &(des_plain[12]), &(out[12]), 12);
    if (memcmp (out, des_cfb_cipher64, 24) != 0)
      { printf ("DES3_CFB64 encrypt error\n"); status = 1; }

    cipher_initdecrypt (ciph, des_cfb_key, 24);
    cipher_setiv (ciph, des_cfb_iv, 8);
    cipher_crypt (ciph, out, in, 17);
    cipher_crypt (ciph, &(out[17]), &(in[17]), 7);
    if (memcmp (in, des_plain, 24) != 0)
      { printf ("DES3_CFB64 decrypt error\n"); status = 1; }
  
    cipher_delete (ciph);
   }
 
  /* DES3_OFB64 */

  printf ("Testing DES3_OFB64...\n");
  memset (in, 0, 40); memset (out, 0, 40);
  desc = cipher_getdescbyname ("DES3_OFB64");

  if (desc)
  {
    ciph = cipher_new (desc);

    cipher_initencrypt (ciph, des_ofb_key, 24);
    cipher_setiv (ciph, des_ofb_iv, 8);
  
    for (i = 0; i < sizeof (des_plain); i++)
      cipher_crypt (ciph, &(des_plain[i]), &(out[i]), 1);
  
    if (memcmp (out, des_ofb_cipherer, 24) != 0)
      { printf ("DES3_OFB64 encrypt error\n"); status = 1; }
  
    cipher_initdecrypt (ciph, des_ofb_key, 24);
    cipher_setiv (ciph, des_ofb_iv, 8);
    cipher_crypt (ciph, out, in, 24);
    if (memcmp (in, des_plain, 24) != 0)
      { printf ("DES3_OFB64 decrypt error\n"); status = 1; }
  
    cipher_delete (ciph);
  }

  /* IDEA_ECB */

  printf ("Testing IDEA_ECB...\n");
  memset (in, 0, 40); memset (out, 0, 40);
  desc = cipher_getdescbyname ("IDEA_ECB");

  if (desc)
  {
    ciph = cipher_new (desc);

    for (i = 0; i < NUM_TESTS-1; i++)
    {
      unsigned char key[16];
  
      memcpy (key, ecb_data[i], 8);
      memcpy (key+8, ecb_data[i+1], 8);
  
      cipher_initencrypt (ciph, key, 16);
      cipher_crypt (ciph, &(plain_data[i][0]), out, 8);
  
      if (memcmp (out, &(idea_data[i][0]), 8) != 0)
        { printf ("IDEA_ECB encrypt error\n"); status = 1; }
  
      cipher_initdecrypt (ciph, key, 16);
      cipher_crypt (ciph, out, out, 8);
      if (memcmp (out, &(plain_data[i][0]), 8) != 0)
        { printf ("IDEA_ECB decrypt error\n"); status = 1; }
    }

    cipher_delete (ciph);
  }

  /* CAST5_ECB */

  printf ("Testing CAST5_ECB...\n");
  memset (in, 0, 40); memset (out, 0, 40);
  desc = cipher_getdescbyname ("CAST5_ECB");

  if (desc)
  {
    unsigned char key[16];
    unsigned char a[16];
    unsigned char b[16];

    ciph = cipher_new (desc);

    memcpy (key, cast_key, 16);

    cipher_initencrypt (ciph, key, 16);
    cipher_crypt (ciph, cast_plain, out, 8);
    if (memcmp (out, cast_cipher128, 8) != 0)
      { printf ("CAST5_ECB encrypt error\n"); status = 1; }

    cipher_initdecrypt (ciph, key, 16);
    cipher_crypt (ciph, out, out, 8);
    if (memcmp (out, cast_plain, 8) != 0)
      { printf ("CAST5_ECB decrypt error\n"); status = 1; }

    cipher_initencrypt (ciph, key, 10);
    cipher_crypt (ciph, cast_plain, out, 8);
    if (memcmp (out, cast_cipher80, 8) != 0)
      { printf ("CAST5_ECB encrypt error\n"); status = 1; }

    cipher_initdecrypt (ciph, key, 10);
    cipher_crypt (ciph, out, out, 8);
    if (memcmp (out, cast_plain, 8) != 0)
      { printf ("CAST5_ECB decrypt error\n"); status = 1; }

    cipher_initencrypt (ciph, key, 5);
    cipher_crypt (ciph, cast_plain, out, 8);
    if (memcmp (out, cast_cipher40, 8) != 0)
      { printf ("CAST5_ECB encrypt error\n"); status = 1; }

    cipher_initdecrypt (ciph, key, 5);
    cipher_crypt (ciph, out, out, 8);
    if (memcmp (out, cast_plain, 8) != 0)
      { printf ("CAST5_ECB decrypt error\n"); status = 1; }
/*
    memcpy (a, cast_avec, 16);
    memcpy (b, cast_bvec, 16);

    for (i = 0; i < 1000000; i++)
    {
      cipher_initencrypt (ciph, b, 16);
      cipher_crypt (ciph, a, a, 8);
      cipher_crypt (ciph, a+8, a+8, 8);
      cipher_initencrypt (ciph, a, 16);
      cipher_crypt (ciph, b, b, 8);
      cipher_crypt (ciph, b+8, b+8, 8);
    }

    if (memcmp (a, cast_aver, 16) != 0)
      { printf ("CAST5_ECB encrypt error\n"); status = 1; }

    if (memcmp (b, cast_bver, 16) != 0)
      { printf ("CAST5_ECB encrypt error\n"); status = 1; }
*/
    cipher_delete (ciph);
  }

  printf ("\n");

  return 0;
}
