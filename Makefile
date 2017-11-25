# Copyright (c) 2017 NDM Systems, Inc. http://www.ndmsystems.com/
# This software is freely distributable, see COPYING for details.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

.PHONY: all clean distclean

NLLDA     = nllda
NLLDO     = nlldo
EXEC_DIR  = /sbin/
UNAME    := $(shell uname)

CPPFLAGS ?= -D_LARGEFILE_SOURCE \
            -D_LARGEFILE64_SOURCE \
            -D_FILE_OFFSET_BITS=64

CFLAGS   ?= -Wall \
            -Winit-self \
            -Wmissing-field-initializers \
            -Wpointer-arith \
            -Wredundant-decls \
            -Wshadow \
            -Wstack-protector \
            -Wswitch-enum \
            -Wundef \
            -fdata-sections \
            -ffunction-sections \
            -fstack-protector-all \
            -ftabstop=4 \
            -g3 \
            -pipe \
            -std=c99

LDFLAGS  ?= -lndm

CFLAGS   += -D_DEFAULT_SOURCE

ifeq ($(UNAME),Linux)
CFLAGS   += -D_POSIX_C_SOURCE=200809L \
            -D_XOPEN_SOURCE=600 \
            -D_SVID_SOURCE=1
endif

all: $(NLLDA) $(NLLDO)

$(NLLDA): nllda.c Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) -o $@

$(NLLDO): nlldo.c Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -fv *.o *~ $(NLLDA) $(NLLDO)

distclean: clean
