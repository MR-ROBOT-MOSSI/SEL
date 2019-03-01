##
## Makefile
##

CC		=	gcc -no-pie

CFLAGS	+=	-W -Wall -Wextra -Werror

SRC		=	challenge3.c \
			utils.c

OBJ		=	$(SRC:.c=.o)

NAME	=	challenge3

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) -o $(NAME) $(OBJ) $(CFLAGS)

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(NAME)

re: fclean all
