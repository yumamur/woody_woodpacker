NAME		= woody_woodpacker

CC			= gcc
CFLAGS		= -Wall -Wextra -Werror
NASM		= nasm
# SSE2 ChaCha20 stub by default; `make STUBDEF=` builds the scalar reference
STUBDEF		= -DUSE_SSE2

SRC			= main.c elf.c pe.c chacha20.c lz4.c
OBJDIR		= obj
OBJ			= $(SRC:%.c=$(OBJDIR)/%.o)

STUB_ASM	= stub/stub.asm
STUB_BIN	= stub.bin
STUB_HDR	= stub.h

STUB32_ASM	= stub/stub32.asm
STUB32_BIN	= stub32.bin
STUB32_HDR	= stub32.h

STUBPE_ASM	= stub/stubpe64.asm
STUBPE_BIN	= stubpe64.bin
STUBPE_HDR	= stubpe64.h

STUBPE32_ASM = stub/stubpe32.asm
STUBPE32_BIN = stubpe32.bin
STUBPE32_HDR = stubpe32.h

all: $(NAME)

$(STUB_BIN): $(STUB_ASM)
	$(NASM) -f bin $(STUBDEF) $< -o $@

$(STUB_HDR): $(STUB_BIN)
	xxd -i $(STUB_BIN) > $(STUB_HDR)

$(STUB32_BIN): $(STUB32_ASM)
	$(NASM) -f bin $< -o $@

$(STUB32_HDR): $(STUB32_BIN)
	xxd -i $(STUB32_BIN) > $(STUB32_HDR)

$(STUBPE_BIN): $(STUBPE_ASM)
	$(NASM) -f bin $(STUBDEF) $< -o $@

$(STUBPE_HDR): $(STUBPE_BIN)
	xxd -i $(STUBPE_BIN) > $(STUBPE_HDR)

$(STUBPE32_BIN): $(STUBPE32_ASM)
	$(NASM) -f bin $< -o $@

$(STUBPE32_HDR): $(STUBPE32_BIN)
	xxd -i $(STUBPE32_BIN) > $(STUBPE32_HDR)

$(OBJDIR)/elf.o: elf.c $(STUB_HDR) $(STUB32_HDR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/pe.o: pe.c $(STUBPE_HDR) $(STUBPE32_HDR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(NAME): $(OBJDIR) $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

asan: CFLAGS += -g -fsanitize=address
asan: clean all

clean:
	rm -fr $(OBJDIR) $(STUB_BIN) $(STUB_HDR) $(STUB32_BIN) $(STUB32_HDR) \
		$(STUBPE_BIN) $(STUBPE_HDR) $(STUBPE32_BIN) $(STUBPE32_HDR)

fclean: clean
	rm -f $(NAME) woody

re: fclean all

t:
	$(CC) $(CFLAGS) -nostdlib -m64 ./test/small64.c -o 1prog_64
	$(CC) $(CFLAGS) -nostdlib -m32 ./test/small32.c -o 2prog_32

test: all
	@$(CC) -Wall -Wextra -O2 test/lz4_test.c lz4.c -o $(OBJDIR)/lz4_test
	@$(CC) -Wall -Wextra -O2 test/chacha_test.c chacha20.c -o $(OBJDIR)/chacha_test
	@$(OBJDIR)/lz4_test
	@$(OBJDIR)/chacha_test
	@sh test/run_tests.sh

.PHONY: all clean fclean re t test asan
