#
#   A wrapper for C++ sockets on Unix and Windows
#   Copyright (C) 2002
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

CXX = g++
#the -g option is for debug
#CXXFLAGS = -g
#the -O3 option is for optimize
#the -Os option is for optimize for size
#the -DNDEBUG option is for not being in debug mode
# CXXFLAGS = -Wall -ansi -pedantic -g
CXXFLAGS = -Wall -ansi -pedantic -g -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
# CXXFLAGS = -Wall -ansi -pedantic -g -DNDEBUG

ifeq ($(shell uname),SunOS)
  LIBS = 
endif

all: DBSniffer

# DBSniffer: dbsniffer.h dbsniffer.cpp util.h util.cpp sniffer.h sniffer.cpp crc.cpp crc.h parser.cpp parser.h learner.cpp learner.h detector.cpp  detector.h XGetopt.cpp XGetopt.h
DBSniffer: dbsniffer.h dbsniffer.cpp crc.h util.h sniffer.h parser.h learner.h detector.h getoptWin32.h
	$(CXX) $(CXXFLAGS) -o DBSniffer dbsniffer.cpp $(LIBS) -lpthread
clean:
	$(RM) DBSniffer


# Apresenta-se aqui o protótipo e os parâmetros que você pode passar para o compilador da gnu (apostila_programacao_c++_v04.pdf):
#
# -v		Mostra detalhes da compilação.
# -wall		Mostra todos os warnings.
# -onome	Define o nome do arquivo de saída (opcional).
# -w		Elimina mensagens de warning.
# -I/path	Acrescenta path include.
# -l/path/lib	Inclue biblioteca (lib).
# -ggdb		Informações extras para o gdb.
# -O		Optimiza o código (-O1,-O2,-O3).
# -c		Somente compila (gera o arquivo *.o).
# -S		Somente compila o arquivo, não linka.
# -lcomplex	Inclue biblioteca dos complexos.
# -lm		Inclue biblioteca matemática.
# -E		Cria somente o arquivo pré-processado.
# -C		Não inclue comentários no executável.
# -g		Gera informações para o debuger (código lento).
# -qdigraph	Adiciona teclas dígrafas.
# -qcompact	Deixa o código mais compacto.
# -xlinguagem	Expecifica a linguagem (C, C++,assembler).
# -p		Informações para o profiler proff.
# -pg		Informações para o groff.
# -m686		Especifica que a máquina alvo é um 686.
# -static	Especifica que a linkagem deve ser estática.
# -p		Especifica inclusão de instruções para o profiler.
# -pg		Especifica inclusão de instruções para o profiler da gnu (gprof ).
# -DNDEBUG	Para remover as macros assert do programa
