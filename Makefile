#################################################################################
# 	Operation Systems (OSs) Course Assignment 3 Makefile			#
# 	Authors: Roy Simanovich and Linor Ronen (c) 2023			#
# 	Description: This Makefile compiles the programs and libraries 		#
# 				Date: 2023-05					#
# 			Course: Operating Systems				#
# 				Assignment: 3					#
# 				Compiler: gcc					#
# 				OS: Linux					#
# 			IDE: Visual Studio Code					#
#################################################################################

# Flags for the compiler and linker.
CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11 -g
RM = rm -f
LIBS = -lcrypto

# Phony targets - targets that are not files but commands to be executed by make.
.PHONY: all default clean

# Default target - compile everything and create the executables and libraries.
all: stnc

# Alias for the default target.
default: all


############
# Programs #
############
stnc: stnc.o stnc_chat.o stnc_perf_c.o stnc_perf_s.o stnc_utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

################
# Object files #
################
%.o: %.c *.h
	$(CC) $(CFLAGS) -c $^
	
#################
# Cleanup files #
#################
clean:
	$(RM) *.gch *.o *.sock stnc