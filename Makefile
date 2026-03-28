CC      = clang
GIT_VER = $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
CFLAGS  = -arch arm64 -Wall -Wextra -I include -I . -DGIT_VERSION='"$(GIT_VER)"'
AS      = clang
ASFLAGS = -arch arm64
BUILD   = build
BIN     = bin

SRCS    = $(wildcard src/*.c)
OBJS    = $(patsubst src/%.c,$(BUILD)/%.o,$(SRCS))
HOOK_OBJS = $(BUILD)/hook_entry.o $(BUILD)/hook_body.o

.PHONY: all shellcode test clean

all: $(BIN)/amfree $(BIN)/test_ent

$(BUILD) $(BIN):
	@mkdir -p $@

# --- Hook (assembly trampoline + C body) ---
$(BUILD)/hook_entry.o: shellcode/hook_entry.S | $(BUILD)
	$(AS) $(ASFLAGS) -c $< -o $@

$(BUILD)/hook_body.o: shellcode/hook_body.c shellcode/data_layout.h | $(BUILD)
	$(CC) $(CFLAGS) -fno-stack-protector -fno-builtin -c $< -o $@



# --- All C sources ---
$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# --- Link (hook_entry.o MUST come before hook_body.o for section order) ---
$(BIN)/amfree: $(OBJS) $(HOOK_OBJS) | $(BIN)
	$(CC) $(CFLAGS) -lobjc -o $@ $^

$(BIN)/test_ent: tests/test_entitlements.c | $(BIN)
	$(CC) $(CFLAGS) -framework Security -framework CoreFoundation -o $@ $<
	codesign -s - --entitlements tests/test_entitlements.plist -f $@

shellcode: $(HOOK_OBJS)
	@size -m $(BUILD)/hook_entry.o | grep inject
	@size -m $(BUILD)/hook_body.o | grep inject

test: $(BIN)/amfree
	@rm -f $(BIN)/test_ent
	@$(MAKE) $(BIN)/test_ent
	@echo "=== Restarting amfid ==="
	@sudo killall -9 debugserver 2>/dev/null || true
	@sleep 1
	@sudo killall -9 amfid 2>/dev/null || true
	@sudo launchctl kickstart -k system/com.apple.MobileFileIntegrity
	@pgrep -x amfid > /dev/null 2>&1 || { echo "[FATAL] amfid did not restart"; exit 1; }
	@echo "=== Injecting ==="
	sudo $(BIN)/amfree -v --path `pwd`
	@echo "=== Testing ==="
	@$(BIN)/test_ent && echo "[PASS]" || echo "[FAIL] $$?"
	@pgrep -x amfid > /dev/null && echo "[OK] amfid alive" || echo "[FAIL] amfid dead"

clean:
	rm -rf $(BUILD) $(BIN)
