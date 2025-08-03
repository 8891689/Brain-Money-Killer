
CC = clang
CC_FLAGS ?= -O3 -march=native -flto -funroll-loops -ffast-math \
            -fomit-frame-pointer -pthread -mavx2

SRCS = main.c lib/sha256_avx.c lib/ripemd160_avx.c

TARGET = Brainmk

all: $(TARGET)

clean:
	@echo "Cleaning up..."
	@rm -f $(TARGET) *.o

build: $(TARGET)

$(TARGET): $(SRCS)
	@echo "Building $(TARGET)..."
	@$(CC) $(CC_FLAGS) $(SRCS) -o $(TARGET)

.PHONY: all clean build
