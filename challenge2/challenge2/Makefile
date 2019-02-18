##
## Makefile
##

CC		=	gcc

CFLAGS	+=	-W -Wall -Wextra -Werror

SRC		=	challenge2.c

OBJ		=	$(SRC:.c=.o)

NAME	=	challenge2

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) -o $(NAME) $(OBJ) $(CFLAGS)

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(NAME)

re: fclean all
