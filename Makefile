NAME		= woody_woodpacker

CC			= gcc
CFLAGS		= -Wall -Wextra -Werror
NASM		= nasm

SRC			= main.c elf.c
OBJDIR		= obj
OBJ			= $(SRC:%.c=$(OBJDIR)/%.o)

STUB_ASM	= stub/stub.asm
STUB_BIN	= stub.bin
STUB_HDR	= stub.h

all: $(NAME)

$(STUB_BIN): $(STUB_ASM)
	$(NASM) -f bin $< -o $@

$(STUB_HDR): $(STUB_BIN)
	xxd -i $(STUB_BIN) > $(STUB_HDR)

$(shell mkdir -p $(OBJDIR))

$(OBJDIR)/main.o: main.c $(STUB_HDR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME)

asan: CFLAGS += -g -fsanitize=address
asan: clean all

clean:
	rm -f $(OBJ) $(STUB_BIN) $(STUB_HDR)

fclean: clean
	rm -f $(NAME) woody

re: fclean all

t:
	$(CC) $(CFLAGS) -nostdlib -m64 ./test/small64.c -o 1prog_64
	$(CC) $(CFLAGS) -nostdlib -m32 ./test/small32.c -o 2prog_32

.PHONY: all clean fclean re t asan
