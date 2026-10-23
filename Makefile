NAME		= woody_woodpacker

CC			= gcc
CFLAGS		= -Wall -Wextra -Werror
NASM		= nasm
# SSE2 ChaCha20 stub by default; `make STUBDEF=` builds the scalar reference
STUBDEF		= -DUSE_SSE2

SRC			= main.c elf.c chacha20.c lz4.c
OBJDIR		= obj
OBJ			= $(SRC:%.c=$(OBJDIR)/%.o)

STUB_ASM	= stub/stub.asm
STUB_BIN	= stub.bin
STUB_HDR	= stub.h

all: $(NAME)

$(STUB_BIN): $(STUB_ASM)
	$(NASM) -f bin $(STUBDEF) $< -o $@

$(STUB_HDR): $(STUB_BIN)
	xxd -i $(STUB_BIN) > $(STUB_HDR)

$(STUB32_BIN): $(STUB32_ASM)
	$(NASM) -f bin $< -o $@

$(STUB32_HDR): $(STUB32_BIN)
	xxd -i $(STUB32_BIN) > $(STUB32_HDR)

$(OBJDIR)/elf.o: elf.c $(STUB_HDR) $(STUB32_HDR)
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
	rm -fr $(OBJDIR) $(STUB_BIN) $(STUB_HDR) $(STUB32_BIN) $(STUB32_HDR)

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
