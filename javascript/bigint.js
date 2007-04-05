/*
 * Copyright (c) 1997-2003  The Stanford SRP Authentication Project
 * All Rights Reserved.
 * See http://srp.stanford.edu/license.txt for details.
 *
 * Any use of this software to demo cryptographic technology other
 * than SRP must include the following acknowledgement:
 * "This software incorporates components derived from the
 *  Secure Remote Password JavaScript demo developed by
 *  Tom Wu (tjw@CS.Stanford.EDU)."
 */

/*
 * BigInteger glue layer:  If we need the applet (IE), access the various
 * java.math.BigInteger constructors through applet methods.  Otherwise
 * (Netscape) just refer to the java constructors directly.
 */

/* Is this Netscape 4.xx? */
var is_ns4 = (navigator.appName == "Netscape" && navigator.appVersion < "5");

/* Do we need the toString() workaround (requires applet)? */
var str_workaround = (navigator.appName == "Opera");

/* Decide whether we need the helper applet or not */
var use_applet = (navigator.appName == "Microsoft Internet Explorer") || (!is_ns4 && navigator.platform.substr(0, 5) == "Linux") || str_workaround;

if(!navigator.javaEnabled()) {
  alert("Java support required for SRP demo");
}

/* Call this at the top of your script after including bigint.js */
function bigint_header() {
}

/* Call this at the end of your webpage - it may instantiate the applet */
function bigint_footer() {
  if(use_applet) {
    document.write('<applet mayscript name="bigint" code="bigint.class" width=1 height=1></applet>');
  }
}

var b64_chr = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./";

function b64tob8(str) {
  var ret = "";
  var d;
  for(var j = 0; j < str.length; ++j) {
    d = b64_chr.indexOf(str.charAt(j));
    ret += hex_chr.charAt((d >> 3) & 7);
    ret += hex_chr.charAt(d & 7);
  }
  return ret;
}

function b8tob64(str) {
  var ret = "";
  var j = 0;
  if((str.length & 1) > 0) {
    ret += str.charAt(0);
    j = 1;
  }
  while(j < str.length) {
    ret += b64_chr.charAt(parseInt(str.substr(j, 2), 8));
    j += 2;
  }
  return ret;
}

/* Accepts radix as second argument */
function parseBigInt(str, r) {
  if(r == 64)
    return parseBigInt(b64tob8(str), 8);
  if(str.length == 0)
    str = "0";
  if(use_applet)
    return document.applets["bigint"].newBigInteger(str, r);
  else
    return new java.math.BigInteger(str, r);
}

/* Use toString() workaround if necessary */
function bigInt2StrHelper(bi, r) {
  if(str_workaround) {
    var i;
    var ret = "";
    var ca = document.applets["bigint"].toCharArray(bi, r);
    for(i = 0; i < ca.length; ++i) {
      ret += String.fromCharCode(ca[i]);
    }
    return ret;
  }
  else
    return bi.toString(r);
}

function bigInt2radix(bi, r) {
  if(r == 64)
    return b8tob64(String(bigInt2StrHelper(bi, 8)));
  else
    return bigInt2StrHelper(bi, r);
}

/*
 * Convert an 8-bit number to its two-character hex representation.
 * (hex_chr is defined in sha1.js)
 */
function hex_byte(num)
{
  return hex_chr.charAt((num >> 4) & 0x0F) + hex_chr.charAt(num & 0x0F);
}

var rng = null;

/*
 * Select a random large integer with a given byte count.
 */
function randomBigInt(bytes) {
  if(use_applet) {
    if(rng == null) {		// This may take a bit of time...
      window.status = "Initializing random number generator...";
      rng = document.applets["bigint"].newSecureRandom();
      window.status = "Done";
    }
    return document.applets["bigint"].newBigIntegerRandom(8 * bytes, rng);
  }
  else {
    if(is_ns4) {
      /* Generate a random integer using Netscape4's RNG */
      var rraw = crypto.random(bytes);
      var rhex = "";
      for(var j = 0; j < bytes; ++j) {
        rhex += hex_byte(rraw.charCodeAt(j));
      }
      return new java.math.BigInteger(rhex, 16);
    }
    else {
      if(rng == null) {
        rng = new java.security.SecureRandom();
      }
      return new java.math.BigInteger(8 * bytes, rng);
    }
  }
}
